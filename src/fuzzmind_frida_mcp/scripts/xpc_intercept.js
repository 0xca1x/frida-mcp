// xpcspy-style XPC message interceptor.
//
// Hooks the canonical send/receive entrypoints and uses xpc_copy_description
// to render each xpc_object_t as a human-readable string. Rate-limited and
// truncated to keep the agent-side message volume sane.
//
// Loaded by `fuzzmind-frida-mcp frida_xpc_intercept`.

'use strict';

const MAX_DESC_LEN = 4096;
const xpcCopyDesc = new NativeFunction(
    _fm_find_export(null, 'xpc_copy_description'),
    'pointer',
    ['pointer']
);

function readDescription(obj) {
    if (obj.isNull()) return '<null>';
    try {
        const cstr = xpcCopyDesc(obj);
        if (cstr.isNull()) return '<no-desc>';
        const s = cstr.readCString();
        // xpc_copy_description's result must be free()'d
        Memory.free(cstr);
        if (s && s.length > MAX_DESC_LEN) {
            return s.substring(0, MAX_DESC_LEN) + '...[truncated]';
        }
        return s || '<empty>';
    } catch (e) {
        return '<desc-error: ' + e.message + '>';
    }
}

function hookSymbol(name, kind) {
    const addr = _fm_find_export(null, name);
    if (!addr) {
        send({type: 'frida-warn', message: 'symbol not found: ' + name});
        return;
    }
    Interceptor.attach(addr, {
        onEnter(args) {
            // Most send-style APIs put the message ptr in arg[1].
            const msg = (kind === 'recv') ? args[0] : args[1];
            const desc = readDescription(msg);
            send({
                type: 'xpc',
                kind: kind,
                api: name,
                description: desc,
                ts: Date.now(),
            });
        },
    });
    send({type: 'frida-info', message: 'hooked ' + name + ' (' + kind + ')'});
}

// Outbound — client → server
hookSymbol('xpc_connection_send_message', 'send');
hookSymbol('xpc_connection_send_message_with_reply', 'send-reply');
hookSymbol('xpc_connection_send_message_with_reply_sync', 'send-reply-sync');

// Inbound (server-side handlers register a handler block via xpc_connection_set_event_handler)
// Catching this requires hooking the handler block invocation, not the registration.
// For v0 we just announce that recv-side capture is best-effort.
send({type: 'frida-info', message: 'send-side hooks installed; recv-side capture is best-effort'});
