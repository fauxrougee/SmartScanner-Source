// Select the node that will be observed for mutations
const targetNode = document.body

// Options for the observer (which mutations to observe)
const config = { attributes: false, childList: true, subtree: true };

// Callback function to execute when mutations are observed
const callback = (mutationList, observer) => {
  for (const mutation of mutationList) {
    if (mutation.type === 'childList') {
      parseNodes(mutation.addedNodes)
    } else if (mutation.type === 'attributes') {
    }
  }
};

// Create an observer instance linked to the callback function
const observer = new MutationObserver(callback);

// Start observing the target node for configured mutations
if (targetNode) {
  observer.observe(targetNode, config);
}


const isDynamicElement = el => {
    if (el.tagName === 'A' && el.href) {
        let isJsLink = el.href.trimLeft().toLowerCase().startsWith('javascript:')
        if (isJsLink) return true;
    }
    let evs = getEventListeners(el);
    // return element if it has events attached
    // only elements with click, change and mouseover events. these are only triggered by scanner
    let hasEvents = evs['click'] || evs['mouseover'] || evs['change'] // Object.keys(evs).length>0
    return hasEvents
}
const dispatchElement = el => {
    try{el.click();}catch(e){}
    try{el.dispatchEvent(evt)}catch(e){}

    var select = el;
    if (select && select.tagName =='SELECT') {
       var optionsCnt = select.options.length
       for (let x=0; x<optionsCnt;x++) {
         select.selectedIndex = x
         var event = document.createEvent('HTMLEvents');
         event.initEvent('change',true,true);
         select.dispatchEvent(event);
       }
    }
}


const parseNodes = nodeList => {
  const selectors = ['a', 'button', 'body', 'select', 'img', 'input', 'div']

  nodeList.forEach(el => {
    
    // init with the element itself
    let elements = [el]
    for (selector of selectors) {
      // find all children
      try {
        elements = elements.concat([...el.querySelectorAll(selector)])
      } catch(e){}
    }

    for (elem of elements) {
      // these elements were hidden, add found links
      if (elem.tagName === 'A' && elem.href) {
        __postReqs.push({
          url:elem.href.trimLeft(),
          method: 'GET',
          headers: {}
        })
      }
      // TODO: evaluate events on elements
      if (isDynamicElement(elem)) {
        dispatchElement(elem)
      }

      // TODO: auto fill and submit forms
    }
    
  })
}








var evt = document.createEvent('MouseEvents');
evt.initMouseEvent('mouseover', true, true, window, 0, 0, 0, 80, 20, false, false, false, false, 0, null);

const selectors = ['a', 'button', 'body', 'select', 'img', 'input', 'div']
let elements = []
for (selector of selectors) {
	elements = elements.concat([...document.querySelectorAll(selector)])
}

elements = elements.filter(isDynamicElement)


async function dispatchEvents() {
    for (let i=0; i<elements.length; i++) {
        dispatchElement(elements[i])
        if (i % (elements.length/5) ===0) await sleep(0);
    }
    await sleep(1)
    __jsEvaluation = await createChannel()
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function createChannel () {
  return new Promise((resolve) => {
    /* eslint-disable-next-line no-new */
    new QWebChannel(qt.webChannelTransport, function (channel) {
      resolve(channel.objects.__jsEvaluation)
    })
  })
}


dispatchEvents().then(async () => {
  await sleep(10)
  __jsEvaluation.done(true)
})
