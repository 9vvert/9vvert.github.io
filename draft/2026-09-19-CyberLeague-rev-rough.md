---
title: CTF Challenge Rough Analysis - vol1
categories: [CTF, ctf-2026]
tags: [rev, web]
---

### CyberLeagueCTF - Digital Vault

index.html: 

```html
......
<div class="checker-box">
  <label for="flag-input">Access code:</label>
  <input id="flag-input" type="text" placeholder="CYBERLEAGUE{...}" size="40"
         autocomplete="off" spellcheck="false">
  <br>
  <button id="check-btn" onclick="checkFlag()">Unlock</button>
  <div id="status">Initialising vault...</div>
  <div id="result" class="info">Loading...</div>
</div>

<script>
  var _cfg = [0xCA, 0xFE, 0xBA, 0xBE];
  var _c = (_cfg[0] << 24 | _cfg[1] << 16 | _cfg[2] << 8 | _cfg[3]) >>> 0;

  var worker = new Worker('worker.js');
  var statusEl = document.getElementById('status');
  var resultEl = document.getElementById('result');
  var checkBtn = document.getElementById('check-btn');

  worker.onerror = function (e) {
    statusEl.textContent = 'Error: ' + e.message;
    resultEl.className = 'wrong';
    resultEl.textContent = 'Failed to initialise vault.';
  };

  worker.onmessage = function (e) {
    var msg = e.data;

    if (msg.type === 'ready') {
      statusEl.textContent = 'Vault ready.';
      resultEl.className = 'info';
      resultEl.textContent = 'Enter the access code and click Unlock.';
      checkBtn.disabled = false;

    } else if (msg.type === 'result') {
      if (msg.success) {
        resultEl.className = 'correct';
        resultEl.textContent = 'Access granted.';
      } else {
        resultEl.className = 'wrong';
        resultEl.textContent = msg.reason
          ? 'Access denied. (' + msg.reason + ')'
          : 'Access denied. Try again.';
      }

    } else if (msg.type === 'error') {
      statusEl.textContent = 'Error: ' + msg.message;
      resultEl.className = 'wrong';
      resultEl.textContent = 'Internal error.';
    }
  };

  worker.postMessage({ type: 'init', cfg: _c });

  function checkFlag() {
    var raw = document.getElementById('flag-input').value.trim();
    if (!raw) {
      resultEl.className = 'info';
      resultEl.textContent = 'Please enter an access code.';
      return;
    }
    resultEl.className = 'info';
    resultEl.textContent = 'Verifying...';

    var enc = new TextEncoder();
    var bytes = enc.encode(raw);
    var masked = new Uint8Array(bytes.length);
    for (var j = 0; j < bytes.length; j++) {
      masked[j] = bytes[j] ^ 0x42;
    }
    worker.postMessage({ type: 'check', payload: Array.from(masked) });
  }

  document.getElementById('flag-input').addEventListener('keydown', function (e) {
    if (e.key === 'Enter' && !checkBtn.disabled) checkFlag();
  });
</script>

</body>
</html>
```

worker.js:

```js
'use strict';

var DB_NAME    = 'vault_store';
var DB_VERSION = 1;
var STORE_NAME = 'state';
var SK_KEY     = 'sk';

var wasmInstance  = null;
var _sk           = null;

function openDB() {
    return new Promise(function (resolve, reject) {
        var req = indexedDB.open(DB_NAME, DB_VERSION);
        req.onupgradeneeded = function (e) {
            var db = e.target.result;
            if (!db.objectStoreNames.contains(STORE_NAME)) {
                db.createObjectStore(STORE_NAME);
            }
        };
        req.onsuccess = function (e) { resolve(e.target.result); };
        req.onerror   = function (e) { reject(e.target.error); };
    });
}

function storeSK(val) {
    return openDB().then(function (db) {
        return new Promise(function (resolve, reject) {
            var tx = db.transaction(STORE_NAME, 'readwrite');
            var st = tx.objectStore(STORE_NAME);
            var rq = st.put(val, SK_KEY);
            rq.onsuccess = function () { resolve(); };
            rq.onerror   = function (e) { reject(e.target.error); };
        });
    });
}

function loadSK() {
    return openDB().then(function (db) {
        return new Promise(function (resolve, reject) {
            var tx = db.transaction(STORE_NAME, 'readonly');
            var st = tx.objectStore(STORE_NAME);
            var rq = st.get(SK_KEY);
            rq.onsuccess = function (e) { resolve(e.target.result); };
            rq.onerror   = function (e) { reject(e.target.error); };
        });
    });
}

function loadWasm() {
    return fetch('checker.wasm')
        .then(function (resp) {
            if (!resp.ok) throw new Error('fetch failed: ' + resp.status);
            return resp.arrayBuffer();
        })
        .then(function (buf) {
            return WebAssembly.instantiate(buf, {});
        })
        .then(function (result) {
            return result.instance;
        });
}

self.onmessage = function (e) {
    var msg = e.data;

    if (msg.type === 'init') {
        loadWasm().then(function (inst) {
            wasmInstance = inst;

            var cfg = msg.cfg >>> 0;
            // cfg = 0xCAFEBABE
            var seed = (cfg ^ 0xFDB97531) >>> 0;
            wasmInstance.exports.f0(seed);

            _sk = (seed ^ 0xDEADBEEF) >>> 0;
            return storeSK(_sk);
        }).then(function () {
            self.postMessage({ type: 'ready' });
        }).catch(function (err) {
            self.postMessage({ type: 'error', message: err.message });
        });

    } else if (msg.type === 'check') {
        if (!wasmInstance) {
            self.postMessage({ type: 'result', success: false, reason: 'not_ready' });
            return;
        }

        loadSK().then(function (stored) {
            if (stored !== _sk) {
                self.postMessage({ type: 'result', success: false, reason: 'bad_state' });
                return;
            }

            var payload = msg.payload;
            var len     = payload.length;
            var mem     = new Uint8Array(wasmInstance.exports.memory.buffer);
            for (var i = 0; i < len; i++) {
                mem[i] = payload[i];
            }

            // f1: check function
            var ok = wasmInstance.exports.f1(0, len, stored);
            self.postMessage({ type: 'result', success: ok === 1 });
        }).catch(function (err) {
            self.postMessage({ type: 'error', message: err.message });
        });

    } else {
        self.postMessage({ type: 'error', message: 'unknown: ' + msg.type });
    }
};
```

`new Worker('worker.js');` this creates web worker in js, which will run in a sperate worker thread.

They will communicate through 'message'. One side use `postMessage`, while the other side register `onmessage` handler.

We can see that the js script put in html starts with `worker.postMessage({ type: 'init', cfg: _c });`,  handled by code after `if (msg.type === 'init')` in worker.js.

Onclicking the button will trigger the check code. In worker.js side, it will eventually call the wasm function.

```
(module
  (type (;0;) (func (param i32)))
  (type (;1;) (func (result i32)))
  (type (;2;) (func (param i32 i32 i32) (result i32)))
  (func (;0;) (type 0) (param i32)
    local.get 0
    global.set 0)
  (func (;1;) (type 1) (result i32)
    global.get 0
    i32.const 1664525
    i32.mul
    i32.const 1013904223
    i32.add
    global.set 0
    global.get 0)
  (func (;2;) (type 2) (param i32 i32 i32) (result i32)
    (local i32 i32 i32 i32 i32 i32 i32 i32)
    local.get 1         ;; arg1, length
    i32.const 33
    i32.ne
    if  ;; label = @1      ;; if not equal, then execute this
      i32.const 0
      return
    end
    local.get 2         ;; arg2, initial key
    i32.const -559038737
    i32.xor
    call 0              ;; set stat = key ^ 0xdeadbeef
    i32.const 0
    local.set 3
    block  ;; label = @1
      loop  ;; label = @2
        local.get 3
        i32.const 33
        i32.ge_u
        br_if 1 (;@1;)    ;; breakout 1 layer, if the value on stack is not zero
        call 1
        i32.const 255
        i32.and
        local.set 5
        ......
        local.get 3
        i32.const 1
        i32.add
        local.set 3
        br 0 (;@2;)
      end
    end
    i32.const 1)
  (memory (;0;) 1)
  (global (;0;) (mut i32) (i32.const 0))
  (export "memory" (memory 0))
  (export "f0" (func 0))
  (export "f1" (func 2))
  (data (;0;) (i32.const 256) "\81\b1\8c\9f\c4\e07\bf\adE\e3\a9H`\df\1af\07\aa\c9\c5/q\bde\e7\04\96 \b0I\22_"))


;; i32.load/store 和memory相关.
```

1. basic stack value read/write

```
  (func (;0;) (type 0) (param i32)
    local.get 0
    global.set 0)
```

`local.get 0` reads the param and put it into stack. Then `global.set 0` pops it and set it as the value of registered global variable 0 - `(global (;0;) (mut i32) (i32.const 0))` (type: i32, initial value: 0.)

Note that the global values are stored in wasm runtime global storage, sperated from `memory`.

2. `data` and `memory`

Define a memory area and export it:
```
(memory (;0;) 1)
(export "memory" (memory 0))
```

So that worker.js can refer to it:
```js
var mem     = new Uint8Array(wasmInstance.exports.memory.buffer);
for (var i = 0; i < len; i++) {
    mem[i] = payload[i];
}
```

And in wasm we can define an area of data, which is stored in memory too.

```
(data (;0;) (i32.const 256) "......")
;; data 0, which is stored in memory address 256 = 0x100.
```

Then we can access to memory data through `load/store` in wasm.

```
;; load an i32 value at memory[12] into stack
i32.const 12
i32.load 

;; store 10 (i32) at the memory[12]
i32.const 12
i32.const 10
i32.store
```


The decrypt code is simple.