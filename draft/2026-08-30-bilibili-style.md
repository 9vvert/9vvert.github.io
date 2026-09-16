---
title: Flash小游戏《小镇的秘密》下载与反编译分析.
categories: [idea&try, GameReverse]
tags: [game, web]
---


```js
                case 68:
                    if (this.panoramaStore.shortcutPrior || this.danmakuStore.state.state)
                        return;
                    if (!this.keydownMap.get(_[i]).status) {
                        this.keydownMap.get(_[i]).status = !0;
                        var r = this.dmSettingStore.toggleDmSwitch()		// 猜测dm是“弹幕”的意思
                          , l = r !== T.cF.Closed;
                        this.shortcutTooltip("shortcut", l ? r === T.cF.Concise ? "精简弹幕" : "开启弹幕" : "关闭弹幕"),
                        this.track.e("shortcut_dmswitch", +!!l)
                    }
                    break;
```

找 this.shortcutTooltip的定义.

```js
i.shortcutTooltip = function(t, e) {
	this.tooltipStore.remove(t),
	this.tooltipStore.create({
		name: t,
		title: e,
		target: this.nodes.videoArea,
		position: p.Zj.CenterCenter
	})
}
```

但是接下来找不到 `tooltipStore.create`的定义了.

我们可以借助控制台来查看。通过调试到特定位置，然后输入`this.tooltipStore`:

```
*r {rootStore: n, rootPlayer: n, nodes: {…}, track: n, dp: {…}, …}*

1. **assetStore**: r {rootStore: n, rootPlayer: n, nodes: {…}, track: n, dp: {…}, …}
2. **auxStore**: r {rootStore: n, rootPlayer: n, nodes: {…}, track: n, dp: {…}, …}
3. **blockStore**: r {rootStore: n, rootPlayer: n, nodes: {…}, track: n, dp: {…}, …}
......
50. **storyStore**: r {rootStore: n, rootPlayer: n, nodes: {…}, track: n, dp: {…}, …}
51. **subtitleStore**: r {rootStore: n, rootPlayer: n, nodes: {…}, track: n, dp: {…}, …}
52. **toastStore**: r {rootStore: n, rootPlayer: n, nodes: {…}, track: n, dp: {…}, …}
53. **tooltipStore**: r {rootStore: n, rootPlayer: n, nodes: {…}, track: n, dp: {…}, …}
54. **track**: n {queues: Array(0), toBeDefined: 'TBD', getRealtimeReportInfo: *ƒ*, reportSender: *ƒ*}
55. **trackStore**: r {rootStore: n, rootPlayer: n, nodes: {…}, track: n, dp: {…}, …}
56. **translationStore**: r {rootStore: n, rootPlayer: n, nodes: {…}, track: n, dp: {…}, …}
57. **uiStore**: r {rootStore: n, rootPlayer: n, nodes: {…}, track: n, dp: {…}, …}
58. **upStore**: r {rootStore: n, rootPlayer: n, nodes: {…}, track: n, dp: {…}, …}
59. **userStore**: r {rootStore: n, rootPlayer: n, nodes: {…}, track: n, dp: {…}, …}
60. **viewTrack**: r {rootStore: n, rootPlayer: n, nodes: {…}, track: n, dp: {…}, …}
61. **wmpStore**: r {rootStore: n, rootPlayer: n, nodes: {…}, track: n, dp: {…}, …}
62. **Symbol(mobx administration)**: n {target\_: r, values\_: Map(1), name\_: 'ObservableObject', defaultAnnotation\_: {…}, keysAtom\_: n, …}
63. **Symbol(mobx-stored-annotations)**: {}
64. defaultState: (...)
65. log: (...)
66. get records: *ƒ ()*
67. set records: *ƒ (r)*
68. [[Prototype]]: r
    1. **onDisconnect**: *ƒ ()*
    2. **tryStartTimerClock**: *ƒ (n)*
    3. **constructor**: *ƒ r(n)*
    4. **create**: *ƒ u()*
    5. **remove**: *ƒ u()*
    6. **update**: *ƒ u()*
    7. **Symbol(mobx-stored-annotations)**: {records: {…}, create: {…}, update: {…}, remove: {…}}
    8. defaultState: (...)
    9. log: (...)
    10. [[Prototype]]: n
        1. **changeState**: *ƒ (n,r)*
        2. **onCommitted**: *ƒ ()*
        3. **onDispose**: *ƒ (n)*
        4. **onGraphFlatten**: *ƒ ()*
        5. **onMount**: *ƒ ()*
        6. **onMounted**: *ƒ ()*
        7. **onNavigate**: *ƒ ()*
        8. **onPrepared**: *ƒ ()*
        9. **onStateCreate**: *ƒ ()*
        10. **onStateCreated**: *ƒ ()*
        11. **onStorageBuild**: *ƒ ()*
        12. **setState**: *ƒ (n,r)*
        13. **constructor**: *ƒ r(n)*
        14. **defaultState**: (...)
        15. log: (...)
        16. get defaultState: *ƒ ()*
        17. [[Prototype]]: Object
```

重要的是最后的`prototype: r`，可以看到这里方法中有`create`, `remove`, `update`等.

```
create : ƒ u() isMobxAction : true length : 0 name : "create" prototype : {} arguments : (...) caller : (...) [[FunctionLocation]] : VM41 core.8a3d87a9.js:1 [[Prototype]] : ƒ () [[Scopes]] : Scopes[6]
```
接着点击定位function location.

```js
 function ta(n, r, i, o) {
	function u() {
		return ts(n, i, r, o || this, arguments)
	}
	return void 0 === i && (i = !1),
	u.isMobxAction = !0,
	ti && (to.value = n,
	T(u, "name", to)),
	u
}
function ts(n, r, i, o, u) {
	var l = tu(n, r, o, u);
	try {
		return i.apply(o, u)
	} catch (n) {
		throw l.error_ = n,
		n
	} finally {
		tl(l)
	}
}
```
混淆的代码，追踪到后面就很难手工分析了.



```
或者用控制台方法：

如果在控制台先输入一次`const ts = this.tooltipStore` (显示undefined正常，因为const赋值语句本来就会返回undefined),  但是下一次再输入ts会显示undefined, 是因为前面的ts作用域已经结束.

可以用 globalThis.ts = ...， 可以跨越多次命令求解.

输入ts.create，显示
ƒ u(){return ts(n,i,r,o||this,arguments)}
```




ta是MobX action wrapper，AI说里面比较重要的是records,

```
n {name_: 'ObservableMap', data_: Map(18), hasMap_: Map(18), keysAtom_: n, enhancer_: ƒ, …}
changeListeners_: undefined
data_: Map(18) {'ctrl:codec:0' => r, 'ctrl:codec:1' => r, 'ctrl:codec:2' => r, 'ctrl:codec:3' => r, 'ctrl:longpress-rate:smart' => r, …}
dehancer: undefined
enhancer_: ƒ em(n,r,i)
hasMap_: Map(18) {'ctrl:codec:0' => r, 'ctrl:codec:1' => r, 'ctrl:codec:2' => r, 'ctrl:codec:3' => r, 'ctrl:longpress-rate:smart' => r, …}
interceptors_: undefined
keysAtom_: n {name_: 'ObservableMap.keys()', isPendingUnobservation_: false, isBeingObserved_: true, observers_: Set(1), diffValue_: 0, …}
name_: "ObservableMap"
Symbol(mobx administration): {}
size: (...)
Symbol(Symbol.toStringTag): (...)
[[Prototype]]: Object
```

在create的时候按下step over, 然后再次检查records，data_部分多了一个"shortcut",

```
changeListeners_: undefined
data_: Map(19)
[[Entries]]
0: {"ctrl:codec:0" => r}
1: {"ctrl:codec:1" => r}
2: {"ctrl:codec:2" => r}
3: {"ctrl:codec:3" => r}
4: {"ctrl:longpress-rate:smart" => r}
5: {"ctrl:loundness:0" => r}
6: {"ctrl:loundness:1" => r}
7: {"ctrl:loundness:2" => r}
8: {"danmaku_switch" => r}
9: {"preventshade" => r}
10: {"special-more" => r}
11: {"feedback-btn" => r}
12: {"ctrl:pip" => r}
13: {"ctrl:fullscreen" => r}
14: {"ctrl:prev" => r}
15: {"ctrl:next" => r}
16: {"ctrl:widescreen" => r}
17: {"ctrl:webscreen" => r}
18: {"shortcut" => r}
size: 19
[[Prototype]]: Map
dehancer: undefined
enhancer_: ƒ em(n,r,i)
hasMap_: Map(19) {'ctrl:codec:0' => r, 'ctrl:codec:1' => r, 'ctrl:codec:2' => r, 'ctrl:codec:3' => r, 'ctrl:longpress-rate:smart' => r, …}
interceptors_: undefined
keysAtom_: n {name_: 'ObservableMap.keys()', isPendingUnobservation_: false, isBeingObserved_: true, observers_: Set(1), diffValue_: 0, …}
name_: "ObservableMap"
Symbol(mobx administration): {}
size: (...)
Symbol(Symbol.toStringTag): (...)
[[Prototype]]: Object
```

重点看这个shortcut, 控制台输入 this.tooltipStore.records.get("shortcut"),

```
{…}
delay: 300
duration: 3000
gap: 6
name: "shortcut"
offsetX: 0
offsetY: 0
position: 5
renderGap: 8
renderTarget: div.bpx-player-tooltip-area
target: div.bpx-player-video-area
timeStamp: 1788073261429
timerClock: r
title: "开启弹幕"
Symbol(mobx administration): n {target_: {…}, values_: Map(13), name_: 'ObservableMap.key', defaultAnnotation_: {…}, keysAtom_: n, …}
get delay: ƒ ()
set delay: ƒ (r)
get duration: ƒ ()
set duration: ƒ (r)
get gap: ƒ ()
set gap: ƒ (r)
get name: ƒ ()
set name: ƒ (r)
......
get title: ƒ ()
set title: ƒ (r)
[[Prototype]]: Object
```


现在开始着手屏蔽.
AI查找相关资料，从DOM层能确定最终屏蔽的对象是`.bpx-player-tooltip-area` (TODO)
```
playTooltipArea:  '.bpx-player-tooltip-area'
playTooltipItem:  '.bpx-player-tooltip-item'
playTooltipTitle: '.bpx-player-tooltip-title'
```

tempmonkey
```js
// ==UserScript==
// @name         Bilibili 隐藏弹幕快捷键提示
// @match        https://www.bilibili.com/video/*
// @run-at       document-start
// @grant        none
// ==/UserScript==

(() => {
    'use strict';

    const blockedTexts = new Set([
        '开启弹幕',
        '关闭弹幕',
        '精简弹幕',
    ]);

    const hideTooltip = (root) => {
        // root 本身也可能就是 title
        const titles = [];

        if (root instanceof Element &&
            root.matches('.bpx-player-tooltip-title')) {
            titles.push(root);
        }

        if (root instanceof Element || root instanceof Document) {
            titles.push(
                ...root.querySelectorAll('.bpx-player-tooltip-title')
            );
        }

        for (const title of titles) {
            if (!blockedTexts.has(title.textContent.trim())) {
                continue;
            }

            const item = title.closest('.bpx-player-tooltip-item');

            if (item) {
                item.style.setProperty('display', 'none', 'important');
            }
        }
    };

    const observer = new MutationObserver(records => {
        for (const record of records) {
            for (const node of record.addedNodes) {
                if (node.nodeType === Node.ELEMENT_NODE) {
                    hideTooltip(node);
                }
            }

            if (record.type === 'characterData') {
                const parent = record.target.parentElement;
                if (parent) {
                    hideTooltip(parent);
                }
            }
        }
    });

    observer.observe(document.documentElement, {
        childList: true,
        subtree: true,
        characterData: true,
    });
})();
```
无效.

新版的也无效：
```js
// ==UserScript==
// @name         Bilibili 隐藏弹幕快捷键提示
// @namespace    http://tampermonkey.net/
// @description  Don't show floated tips when using "d" in bilibili
// @version      AngelBeats!
// @match        https://www.bilibili.com/*
// @run-at       document-start
// @grant        none
// ==/UserScript==

(() => {
    'use strict';

    const blockedTexts = new Set([
        '开启弹幕',
        '关闭弹幕',
        '精简弹幕',
    ]);

    function checkTitle(title) {
        if (!title?.matches?.('.bpx-player-tooltip-title')) {
            return;
        }

        const item = title.closest('.bpx-player-tooltip-item');
        if (!item) {
            return;
        }

        const blocked = blockedTexts.has(title.textContent.trim());

        if (blocked) {
            item.style.setProperty('display', 'none', 'important');
        } else {
            // Bilibili 可能复用同一个 tooltip-item，
            // 所以显示其他提示时要撤掉我们加的 display:none。
            if (item.style.getPropertyPriority('display') === 'important' &&
                item.style.display === 'none') {
                item.style.removeProperty('display');
            }
        }
    }

    function checkNode(node) {
        if (!(node instanceof Element)) {
            return;
        }

        if (node.matches('.bpx-player-tooltip-title')) {
            checkTitle(node);
        }

        for (const title of node.querySelectorAll('.bpx-player-tooltip-title')) {
            checkTitle(title);
        }
    }

    function start() {
        // 先处理已经存在的节点
        for (const title of document.querySelectorAll('.bpx-player-tooltip-title')) {
            checkTitle(title);
        }

        const observer = new MutationObserver(records => {
            for (const record of records) {

                // 关键：
                // textContent = "开启弹幕" 往往表现为
                // title 元素内部 Text Node 被替换。
                //
                // 所以检查 record.target，而不仅仅是 addedNodes。
                if (record.target instanceof Element) {
                    checkNode(record.target);
                }

                // 同时处理真正新增的 tooltip DOM
                for (const node of record.addedNodes) {
                    if (node instanceof Element) {
                        checkNode(node);
                    }
                }
            }
        });

        observer.observe(document.documentElement, {
            childList: true,
            subtree: true,
            characterData: true,
        });
    }

    if (document.documentElement) {
        start();
    } else {
        new MutationObserver((_, observer) => {
            if (document.documentElement) {
                observer.disconnect();
                start();
            }
        }).observe(document, {
            childList: true,
        });
    }
})();
```












ver2: 直接隐藏，也无效:
```js
// ==UserScript==
// @name         Bilibili 隐藏 D 键弹幕提示
// @namespace    http://tampermonkey.net/
// @description  Hide danmaku shortcut tooltip when pressing D
// @version      1.0
// @match        https://www.bilibili.com/*
// @run-at       document-start
// @grant        none
// ==/UserScript==

(() => {
    'use strict';

    const style = document.createElement('style');

    style.textContent = `
        html.tm-hide-danmaku-tip
        .bpx-player-tooltip-item[data-name="shortcut"] {
            display: none !important;
            visibility: hidden !important;
            opacity: 0 !important;
        }
    `;

    (document.head || document.documentElement).appendChild(style);

    let timer = null;

    window.addEventListener('keydown', e => {
        if (
            e.code !== 'KeyD' &&
            e.key?.toLowerCase() !== 'd'
        ) {
            return;
        }

        document.documentElement.classList.add(
            'tm-hide-danmaku-tip'
        );

        clearTimeout(timer);

        // Bilibili 的 shortcut tooltip 会存在一段时间，
        // 在这期间直接通过 CSS 禁止显示。
        timer = setTimeout(() => {
            document.documentElement.classList.remove(
                'tm-hide-danmaku-tip'
            );
        }, 2500);
    }, true);
})();
```

最后发现script根本没有执行，原因是需要提前在chrome://extension -> tempmonkey -> detail中勾选allow user script.