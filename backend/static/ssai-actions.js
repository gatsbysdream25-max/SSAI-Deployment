/* Button actions without inline handlers (the page's Content-Security-Policy forbids onclick="..." and friends).
 *
 * Markup:  <button data-on-click="setMode" data-args='["home"]'>   (also data-on-change, data-on-keydown)
 *          data-pass="event" | "this"   prepend the event / the element to the arguments
 *          data-key="Enter"             keydown only: act on that key alone
 * A page registers the functions its markup may call: SSAI.register({ setMode, ... }).
 * Only registered names run, and the arguments are parsed as JSON, so text that reaches an attribute (a threat's title,
 * a machine name) can choose among the page's own functions at worst, and can never become code. */
(function (w, d) {
  'use strict';
  var table = Object.create(null);
  w.SSAI = {
    register: function (fns) {
      Object.keys(fns).forEach(function (name) { if (typeof fns[name] === 'function') table[name] = fns[name]; });
    }
  };
  function dispatch(ev) {
    var attr = 'data-on-' + ev.type;
    var el = ev.target && ev.target.closest ? ev.target.closest('[' + attr + ']') : null;
    if (!el) return;
    var fn = table[el.getAttribute(attr)];
    if (!fn) return;
    if (ev.type === 'keydown' && el.hasAttribute('data-key') && ev.key !== el.getAttribute('data-key')) return;
    var args;
    try { args = JSON.parse(el.getAttribute('data-args') || '[]'); } catch (e) { return; }
    if (!Array.isArray(args)) return;
    var pass = el.getAttribute('data-pass');
    if (pass === 'event') args.unshift(ev); else if (pass === 'this') args.unshift(el);
    fn.apply(el, args);
  }
  ['click', 'change', 'keydown'].forEach(function (type) { d.addEventListener(type, dispatch); });
})(window, document);
