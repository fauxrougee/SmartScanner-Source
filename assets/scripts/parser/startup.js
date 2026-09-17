// crawler-parser-page-overide-ajax.js
let __orgFetch = window.fetch
let __postReqs = []

function _flushAjaxReuqests() {
  let posts = __postReqs
  __postReqs = []
  return posts
}

window.fetch = async (resource, init) => {
  let url, method, body, headers
  if (resource instanceof Request) {
    // request object
    url = resource.url
    method = init?.method || resource.method
    method = method.toUpperCase()
    body = init?.body
    headers = init?.headers || resource.headers
    let noBodyRequired = method === 'GET' || method === 'HEAD'
    if (!noBodyRequired && !body) {
      body = await resource.text()
      let resource2 = new Request(url, {
        method,
        headers: resource.headers,
        mode: resource.mode,
        credentials: resource.credentials,
        cache: resource.cache,
        redirect: resource.redirect,
        referrer: resource.referrer,
        integrity: resource.integrity,
        body
      })
      resource = resource2
    }
  } else {
    url = resource.toString()
    method = init?.method || 'GET'
    body = init?.body
    headers = init?.headers
  }
  let headersObj = {}
  if (headers instanceof Headers) {
    for (const pair of headers) {
      headersObj[pair[0]] = pair[1]
    }
  } else {
    for (const headerName in headers) {
      headersObj[headerName] = headers[headerName]
    }
  }
  
  __postReqs.push ({method, url, body, headers:headersObj})
	return __orgFetch(resource, init)
}

// track XMLHttpRequest class
const __TRACK_SYMBOLS = Symbol()

function __trackXmlObject(xhttpProto) {
  xhttpProto['open'] = new Proxy(xhttpProto['open'], {
    apply(func, obj, args) {
      obj[__TRACK_SYMBOLS] = {
        method: args[0],
        url: args[1],
        //'async': args[2],
        credentials: {
          user: args[3],
          password: args[4]
        },
        headers: {}
      }
      return Reflect.apply(...arguments);
    }
  })
   
  xhttpProto['setRequestHeader'] = new Proxy(xhttpProto['setRequestHeader'], {
    apply(func, obj, args) {
      const req = obj[__TRACK_SYMBOLS]
      req.headers[args[0]] = (req.headers[args[0]] || '') + args[1]
      return Reflect.apply(...arguments);
    }
  })
  
  xhttpProto['send'] = new Proxy(xhttpProto['send'], {
    apply(func, obj, args) {
      const req = obj[__TRACK_SYMBOLS]
      req.body = args[0]
      __postReqs.push(req)
      return Reflect.apply(...arguments);
    }
  })
}

const __ORG_XMLHttpRequest_PROTOTYPE = XMLHttpRequest.prototype
__trackXmlObject(XMLHttpRequest.prototype);
// end of crawler-parser-page-overide-ajax.js


// https://github.com/alex2844/js-events
if (!('getEventListeners' in window)) {
	getEventListeners = function(el) {
		let _ev,
			_evs = Object.assign({}, (el._events || {}));
		for (let ev in el) {
			if (/^on/.test(ev) && (typeof(el[ev]) === 'function') && (_ev = ev.slice(2))) {
				if (!_evs[_ev])
					_evs[_ev] = [];
				_evs[_ev].push({
					listener: el[ev],
					useCapture: false,
					passive: false,
					once: false,
					type: _ev
				});
			}
		}
		return _evs;
	}
	EventTarget.prototype._addEventListener = EventTarget.prototype.addEventListener;
	EventTarget.prototype._removeEventListener = EventTarget.prototype.removeEventListener;
	EventTarget.prototype.addEventListener = function(a, b, c) {
		if (c == undefined)
			c = false;
		if (c && c.once) {
			let _b = b;
			b = function() {
				this.removeEventListener(a, b, false, true);
				_b.apply(this, arguments);
			};
		}
		this._addEventListener(a, b, c);
		if (!this._events) {
			this._events = {};
			Object.defineProperty(this, '_events', { enumerable: false });
		}
		if (!this._events[a])
			this._events[a] = [];
		this._events[a].push({
			listener: b,
			useCapture: (((c === true) || (c.capture)) || false),
			passive: ((c && c.passive) || false),
			once: ((c && c.once) || false),
			type: a
		});
	}
	EventTarget.prototype.removeEventListener = function(a, b, c, s) {
		if (c == undefined)
			c = false;
		if (!s)
			this._removeEventListener(a, b, c);
		if (this._events && this._events[a]) {
			for (var i=0; i<this._events[a].length; ++i) {
				if ((this._events[a][i].listener == b) && (this._events[a][i].useCapture == c)) {
					this._events[a].splice(i, 1);
					break;
				}
			}
			if (this._events[a].length == 0)
				delete this._events[a];
		}
	}
}
Element.prototype.on = function(event, callback, options) {
	this.addEventListener(event, callback, options);
	return this;
}
Element.prototype.off = function (event, callback, options) {
	this.removeEventListener(event, callback, options);
	return this;
}
Element.prototype.emit = function (event, args=null) {
	this.dispatchEvent(new CustomEvent(event, {detail: args}));
	return this;
}
Object.defineProperties(Element.prototype, {
	on: { enumerable: false },
	off: { enumerable: false },
	emit: { enumerable: false }
});
