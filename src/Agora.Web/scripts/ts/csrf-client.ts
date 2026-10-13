type CsrfAwareXhr = XMLHttpRequest & {
  _csrfMethod?: string;
  _csrfUrl?: string;
};

(() => {
  const cookieName = 'agora.csrf.request';
  const formFieldName = '__RequestVerificationToken';
  const headerName = 'X-CSRF-TOKEN';

  const getCookie = (name: string): string => {
    const prefix = `${name}=`;
    const parts = document.cookie ? document.cookie.split(';') : [];
    for (const part of parts) {
      const value = part.trim();
      if (value.startsWith(prefix)) {
        return decodeURIComponent(value.slice(prefix.length));
      }
    }
    return '';
  };

  const csrfToken = getCookie(cookieName);
  if (!csrfToken) return;

  const isUnsafeMethod = (method: string | undefined | null): boolean => {
    const upper = (method || 'GET').toUpperCase();
    return upper !== 'GET' && upper !== 'HEAD' && upper !== 'OPTIONS' && upper !== 'TRACE';
  };

  const isSameOriginUrl = (input: string | URL | undefined | null): boolean => {
    try {
      const url = new URL(input || window.location.href, window.location.href);
      return url.origin === window.location.origin;
    } catch {
      return false;
    }
  };

  document.querySelectorAll<HTMLFormElement>('form').forEach((form) => {
    const method = form.getAttribute('method') || 'GET';
    if (!isUnsafeMethod(method)) return;
    if (form.querySelector(`input[name="${formFieldName}"]`)) return;

    const input = document.createElement('input');
    input.type = 'hidden';
    input.name = formFieldName;
    input.value = csrfToken;
    form.appendChild(input);
  });

  const originalFetch = window.fetch.bind(window);
  window.fetch = (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const method = init?.method || 'GET';
    const url = typeof input === 'string' || input instanceof URL ? String(input) : input.url;

    if (!isUnsafeMethod(method) || !isSameOriginUrl(url)) {
      return originalFetch(input, init);
    }

    const requestInit: RequestInit = init ? { ...init } : {};
    const headers = new Headers(requestInit.headers || (input instanceof Request ? input.headers : undefined));
    if (!headers.has(headerName)) {
      headers.set(headerName, csrfToken);
    }
    requestInit.headers = headers;

    return originalFetch(input, requestInit);
  };

  const originalOpen = XMLHttpRequest.prototype.open;
  const originalSend = XMLHttpRequest.prototype.send;

  XMLHttpRequest.prototype.open = function(
    this: CsrfAwareXhr,
    method: string,
    url: string | URL,
    async?: boolean,
    username?: string | null,
    password?: string | null
  ): void {
    this._csrfMethod = method || 'GET';
    this._csrfUrl = String(url || window.location.href);
    originalOpen.call(this, method, String(url), async ?? true, username ?? null, password ?? null);
  };

  XMLHttpRequest.prototype.send = function(this: CsrfAwareXhr, body?: Document | XMLHttpRequestBodyInit | null): void {
    if (isUnsafeMethod(this._csrfMethod) && isSameOriginUrl(this._csrfUrl)) {
      this.setRequestHeader(headerName, csrfToken);
    }
    originalSend.call(this, body ?? null);
  };
})();
