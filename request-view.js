(() => {
  function build(requests, isVisible, sortKey, direction) {
    const visible = [];
    for (const request of requests) {
      if (isVisible(request)) visible.push(request);
    }
    visible.sort((a, b) => {
      let left = a[sortKey];
      let right = b[sortKey];
      if (["url", "method", "type"].includes(sortKey)) {
        left = String(left);
        right = String(right);
      } else {
        left = Number(left) || 0;
        right = Number(right) || 0;
      }
      return left < right ? -direction : left > right ? direction : 0;
    });
    return visible;
  }

  function hasOnlyBoundedQuantifiers(source) {
    if (source.length > 256) return false;
    let inClass = false;
    for (let index = 0; index < source.length; index++) {
      const character = source[index];
      if (character === "\\") {
        index++;
        continue;
      }
      if (character === "[") inClass = true;
      else if (character === "]" && inClass) inClass = false;
      else if (!inClass && (character === "*" || character === "+"))
        return false;
      else if (!inClass && character === "{") {
        const end = source.indexOf("}", index + 1);
        if (end < 0) continue;
        const expression = source.slice(index + 1, end);
        const comma = expression.indexOf(",");
        if (comma >= 0) {
          const upper = expression.slice(comma + 1);
          if (!upper || Number(upper) > 1000) return false;
        } else if (expression && Number(expression) > 1000) {
          return false;
        }
      }
    }
    return true;
  }

  window.CleanInspectRequestView = {
    build,
    dataUrlVisible: (hideData) => !hideData,
    hasOnlyBoundedQuantifiers,
  };
})();
