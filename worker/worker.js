/**
 * LaserRx streaming Worker — Cloudflare.
 *
 * Alcance (Opción A, aprobada): este Worker NO conoce Drive, ni Sheets, ni el
 * router, ni el mapeo key->fileId. n8n arma el payload completo (system con los
 * DOS breakpoints de cache_control) y este Worker solo lo transmite.
 *
 * La API key de Anthropic vive SOLO aquí. Las credenciales de Google viven SOLO
 * en n8n. Ninguna cruza.
 *
 * Secretos / bindings esperados:
 *   ANTHROPIC_API_KEY   secret   x-api-key para api.anthropic.com
 *   TOKEN_PUBKEY_B64    secret   clave PUBLICA Ed25519 (raw 32B, base64url)
 *   N8N_BASE            var      https://laserai.app.n8n.cloud/webhook
 *   N8N_INTERNAL_SECRET secret   cabecera compartida con los endpoints internos
 *   ALLOWED_ORIGIN      var      LISTA de origenes permitidos, separados por comas.
 *                               La fuente de verdad es wrangler.toml [vars], no el
 *                               panel: con builds desde el repo, el fichero pisa
 *                               cualquier valor puesto a mano en Settings.
 *   OPENS               KV       contador de aperturas por cadena (cid)
 *
 * El Worker solo VERIFICA firmas (clave pública). No puede acuñar tokens aunque
 * se comprometa por completo: la clave privada está en n8n.
 */

// ── Topes. DOS contadores con ventanas distintas, cada uno derivado de su propia
//    medición sobre las 368 consultas reales de Consultations:
//
//    SESSION_CAP  ráfaga. Se reinicia tras IDLE_RESET de inactividad, igual que
//                 la definición de sesión del análisis (gap >15 min).
//                 Consultas por sesión: p95=10, p99=22, MAX=28 -> 30 no corta
//                 ninguna de las 104 sesiones observadas.
//    CHAIN_CAP    techo absoluto de la cadena, no se reinicia nunca; muere con rexp.
//                 Consultas en ventana de 8 h: p95=34, p99=45, MAX=49 -> 70.
//
//    Ninguno sirve solo: SESSION_CAP a secas se puede eludir esperando 15 min entre
//    ráfagas; CHAIN_CAP a secas tendría que valer ~70 y no acota el consumo rápido.
const SESSION_CAP = 30;
const CHAIN_CAP = 70;
const IDLE_RESET = 15 * 60;   // segundos de inactividad que reinician la ráfaga
const KBMISS = '[[KB_MISS]]';

// ─────────────────────────────────────────── utilidades

const enc = new TextEncoder();
const dec = new TextDecoder();

function b64urlToBytes(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// ALLOWED_ORIGIN es una lista separada por comas. Se devuelve el origen de la
// petición SOLO si está en la lista; si no, el primero de la lista.
//
// Nunca se refleja un origen no listado: eso convertiría el CORS en un pase
// libre. Y se devuelve un origen concreto en vez de '*' porque el cliente manda
// cabecera Authorization, y con credenciales el comodín no vale.
//
// Vary: Origin es obligatorio. Sin él, cualquier caché intermedia puede servir a
// un origen la respuesta cacheada para otro, y el navegador la rechaza — un
// fallo intermitente que depende de quién pasó antes por esa caché.
function corsHeaders(env, request) {
  const lista = String(env.ALLOWED_ORIGIN || '*')
    .split(',').map((s) => s.trim()).filter(Boolean);
  const origen = request?.headers?.get('origin') || '';
  const permitido = lista.includes(origen) ? origen : (lista[0] || '*');
  return {
    'Access-Control-Allow-Origin': permitido,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'authorization, content-type',
    'Access-Control-Max-Age': '86400',
    Vary: 'Origin',
  };
}

function jsonError(status, code, message, env, request) {
  return new Response(JSON.stringify({ error: code, message }), {
    status,
    headers: { 'content-type': 'application/json', ...corsHeaders(env, request) },
  });
}

/** Verifica el token Ed25519 y devuelve sus claims, o null. */
async function verifyToken(token, env) {
  if (!token || token.indexOf('.') < 0) return null;
  const [payloadB64, sigB64] = token.split('.');
  if (!payloadB64 || !sigB64) return null;
  let claims;
  try {
    claims = JSON.parse(dec.decode(b64urlToBytes(payloadB64)));
  } catch { return null; }

  let key;
  try {
    key = await crypto.subtle.importKey(
      'raw', b64urlToBytes(env.TOKEN_PUBKEY_B64),
      { name: 'Ed25519' }, false, ['verify'],
    );
  } catch { return null; }

  const ok = await crypto.subtle.verify(
    { name: 'Ed25519' }, key, b64urlToBytes(sigB64), enc.encode(payloadB64),
  );
  return ok ? claims : null;
}

// ─────────────────────────────────────────── frames SSE

function sse(event, dataObj) {
  return enc.encode(`event: ${event}\ndata: ${JSON.stringify(dataObj)}\n\n`);
}

// ─────────────────────────────────────────── handler principal

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(env, request) });
    }
    if (url.pathname === '/issue' && request.method === 'POST') {
      return handleIssue(request, env);
    }
    if (url.pathname === '/renew' && request.method === 'POST') {
      return handleRenew(request, env);
    }
    if (url.pathname !== '/stream' || request.method !== 'POST') {
      return jsonError(404, 'not_found', 'Ruta no encontrada.', env, request);
    }
    return handleStream(request, env, ctx);
  },
};

// ─────────────────────────────────────────── /issue
// Arranque de la cadena. El navegador manda el Row ID de Glide (k) y recibe un
// token de 20 min. El SECRETO INTERNO no sale de aquí: el Worker lo añade al
// hablar con n8n, así que la página nunca lo ve.
//
// Por qué el Row ID y no el email: un email ajeno se adivina o se conoce, y
// bastaría cambiarlo en la URL para gastar créditos de otro. El Row ID son 22
// caracteres aleatorios que solo tiene el dueño de esa fila. Quien es el usuario
// lo RESUELVE n8n leyendo Members; el cliente no lo declara.

async function handleIssue(request, env) {
  let body;
  try { body = await request.json(); } catch { body = {}; }
  const k = (body.k || '').toString().trim();
  if (!k) return jsonError(400, 'missing_key', 'Falta el identificador de usuario.', env, request);

  let r;
  try {
    r = await fetch(`${env.N8N_BASE}/internal-issue`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-internal-secret': env.N8N_INTERNAL_SECRET },
      body: JSON.stringify({ k }),
    });
  } catch {
    return jsonError(502, 'issue_failed', 'No se pudo iniciar la sesión.', env, request);
  }
  if (!r.ok) return jsonError(502, 'issue_failed', 'No se pudo iniciar la sesión.', env, request);

  let out;
  try { out = await r.json(); } catch { out = {}; }

  // n8n responde 200 con {error:...} en los rechazos de negocio.
  if (out.error === 'not_a_member') {
    return jsonError(401, 'not_a_member', 'Tu cuenta no está activa en LaserRx.', env, request);
  }
  if (out.error === 'plan_excluded') {
    return jsonError(403, 'plan_excluded', 'Tu plan no incluye este módulo.', env, request);
  }
  if (!out.token) return jsonError(502, 'issue_failed', 'No se pudo iniciar la sesión.', env, request);

  return new Response(JSON.stringify({ token: out.token, exp: out.exp, rexp: out.rexp }), {
    headers: { 'content-type': 'application/json', ...corsHeaders(env, request) },
  });
}

// ─────────────────────────────────────────── /renew
// El Worker verifica y delega el ACUÑADO a n8n, que tiene la clave privada.

async function handleRenew(request, env) {
  const auth = request.headers.get('authorization') || '';
  const token = auth.replace(/^Bearer\s+/i, '');
  const claims = await verifyToken(token, env);

  if (!claims) return jsonError(401, 'bad_token', 'Token inválido.', env, request);

  const now = Math.floor(Date.now() / 1000);
  // rexp es el techo ABSOLUTO de la cadena: la renovación no lo extiende nunca.
  if (!claims.rexp || now >= claims.rexp) {
    return jsonError(401, 'chain_expired', 'La sesión caducó del todo.', env, request);
  }

  const r = await fetch(`${env.N8N_BASE}/internal-renew`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-internal-secret': env.N8N_INTERNAL_SECRET },
    body: JSON.stringify({ sub: claims.sub, cid: claims.cid, rexp: claims.rexp }),
  });
  if (!r.ok) return jsonError(502, 'renew_failed', 'No se pudo renovar.', env, request);

  const body = await r.json();
  return new Response(JSON.stringify({ token: body.token }), {
    headers: { 'content-type': 'application/json', ...corsHeaders(env, request) },
  });
}

// ─────────────────────────────────────────── /stream

async function handleStream(request, env, ctx) {
  const auth = request.headers.get('authorization') || '';
  const token = auth.replace(/^Bearer\s+/i, '');
  const claims = await verifyToken(token, env);

  // ── Errores previos al SSE: HTTP real. Ninguno cobra crédito, porque el
  //    cobro ocurre en n8n /internal-prepare, más abajo. El reintento tras un
  //    401 es seguro por construcción.
  if (!claims) return jsonError(401, 'bad_token', 'Token inválido.', env, request);

  const now = Math.floor(Date.now() / 1000);
  if (!claims.exp || now >= claims.exp) {
    return jsonError(401, 'token_expired', 'Token caducado; renueva.', env, request);
  }

  // ── Contadores sobre la CADENA (cid), no sobre el jti: renovar cambia el jti
  //    pero conserva el cid, así que renovar no reinicia nada.
  //    KV es eventualmente consistente, así que estos contadores son aproximados.
  //    Eso es aceptable: son un límite de seguridad, no la facturación — el cobro
  //    autoritativo es el descuento de crédito en n8n.
  const key = `cid:${claims.cid}`;
  let st = { n: 0, s: 0, last: 0 };
  try { st = JSON.parse((await env.OPENS.get(key)) || '') || st; } catch {}
  if (now - (st.last || 0) > IDLE_RESET) st.s = 0;   // ráfaga nueva

  if (st.s >= SESSION_CAP) {
    return jsonError(429, 'session_cap',
      'Demasiadas consultas seguidas. Espera unos minutos y podrás continuar.', env, request);
  }
  if (st.n >= CHAIN_CAP) {
    return jsonError(429, 'chain_cap',
      'Alcanzaste el máximo de consultas de esta sesión de trabajo.', env, request);
  }
  // OJO: aquí NO se incrementa. El contador sube en pump(), solo cuando
  // /internal-prepare confirma que la consulta prosperó. Si n8n devuelve 402
  // (sin créditos) o 403 (plan), el intento no consume cupo.
  // Consecuencia aceptada: dos peticiones concurrentes pueden pasar el chequeo
  // antes de que ninguna incremente. Es un límite de seguridad aproximado —
  // KV es eventualmente consistente de todos modos — y la facturación
  // autoritativa es el descuento de crédito en n8n, no este contador.

  let body;
  try { body = await request.json(); } catch { body = {}; }
  const q = (body.q || '').toString().slice(0, 4000);
  const lang = (body.lang || 'es').toString();
  if (!q.trim()) return jsonError(400, 'empty_query', 'Consulta vacía.', env, request);

  // ── Contrato completo hacia /internal-prepare.
  //    history: solo los últimos 20 turnos. El tope es del Worker, no del cliente:
  //    un history largo infla el payload y el coste de tokens aguas abajo.
  //    is_first_message: se conserva el TRI-ESTADO. n8n distingue false de ausente
  //    para decidir si cobra crédito, así que un `|| false` aquí cambiaría la
  //    facturación. Si el cliente no lo manda, va null y n8n aplica su default.
  const history = Array.isArray(body.history) ? body.history.slice(-20) : [];
  const isFirstMessage = typeof body.is_first_message === 'boolean'
    ? body.is_first_message
    : null;
  const mod = (body.module || '').toString().slice(0, 40) || null;
  // Vocabulario canonico del cliente. `procedure_id` y `procedure_sub_id` son
  // ESTABLES entre idiomas; `procedure_es` y `procedure_sub_es` son la etiqueta
  // canonica en espaniol, para que n8n componga la consulta del router
  // desacoplada del idioma del usuario. Ampliar esta lista blanca es lo unico
  // que hace falta: sin esto el cliente los manda y aqui se pierden.
  const S80 = (v) => (v === undefined || v === null) ? '' : String(v).slice(0, 80);
  const proc = {
    procedure_id: S80(body.procedure_id),
    procedure_sub_id: S80(body.procedure_sub_id),
    procedure_es: S80(body.procedure_es),
    procedure_sub_es: S80(body.procedure_sub_es),
    // procedure_other: el chip "Otro" manda los cuatro identificadores vacios a
    // proposito, y sin este campo el procedimiento solo viajaria dentro de `q`.
    procedure_other: S80(body.procedure_other),
    // wavelength: la necesita la primera tabla del subworkflow de PubMed para
    // resolver la FAMILIA del laser. Sin ella la consulta cae al texto libre y
    // encuentra bastante menos — medido contra Validate, que si la manda.
    wavelength: S80(body.wavelength),
  };

  const { readable, writable } = new TransformStream();
  const writer = writable.getWriter();

  // El SSE se abre YA. Todo lo que falle a partir de aquí viaja como frame.
  ctx.waitUntil(pump(writer, {
    claims, q, lang, history, isFirstMessage, mod, proc, env, ctx, key, st, now,
  }));

  return new Response(readable, {
    headers: {
      'content-type': 'text/event-stream; charset=utf-8',
      'cache-control': 'no-cache, no-transform',
      connection: 'keep-alive',
      'x-accel-buffering': 'no',
      ...corsHeaders(env, request),
    },
  });
}

// ─────────────────────────────────────────── bucle de trabajo

async function pump(writer, {
  claims, q, lang, history, isFirstMessage, mod, proc, env, ctx, key, st, now,
}) {
  const t0 = Date.now();
  const send = (ev, d) => writer.write(sse(ev, d));
  let full = '';
  let kbMiss = false;
  let usage = {};
  let prep = null;
  // AQUI y no dentro del try: el `finally` las lee para componer el finalize, y
  // un `let` declarado dentro del try NO es visible desde el finally. Estuvieron
  // dentro y el efecto no fue un campo vacio sino MUCHO peor: el JSON.stringify
  // lanzaba ReferenceError, el ctx.waitUntil no llegaba a ejecutarse y se perdia
  // el finalize ENTERO — Consultations, el correo de KB faltante y KB_Gaps— en
  // TODOS los turnos, tambien los normales.
  let kbPmids = '';
  let kbHits = 0;
  let kbGapKey = '';

  try {
    // Etapas mapeadas al pre-stream real medido en producción (exec 4399, 8.89 s):
    //   auth ~0-4 s · routing ~4-7 s · loading_kb ~7-9 s
    await send('status', { stage: 'auth' });
    const tRoute = setTimeout(() => send('status', { stage: 'routing' }), 4000);
    const tKb = setTimeout(() => send('status', { stage: 'loading_kb' }), 7000);

    const r = await fetch(`${env.N8N_BASE}/internal-prepare`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-internal-secret': env.N8N_INTERNAL_SECRET },
      body: JSON.stringify({
        email: claims.sub, q, lang, cid: claims.cid,
        history, is_first_message: isFirstMessage, module: mod,
        ...proc,
      }),
    });
    clearTimeout(tRoute); clearTimeout(tKb);

    if (!r.ok) {
      await send('error', { code: 502, message: 'Fallo preparando la consulta.' });
      return;
    }
    prep = await r.json();

    // Errores de negocio: el SSE ya está abierto, así que van como frame.
    if (prep.error) {
      const code = prep.error === 'no_credits' ? 402
                 : prep.error === 'plan_excluded' ? 403 : 502;
      await send('error', { code, message: prep.message || 'No autorizado.' });
      return;
    }

    // ── El intento prosperó: AHORA sí consume cupo. Un 402/403 no llega aquí.
    ctx.waitUntil(env.OPENS.put(
      key, JSON.stringify({ n: st.n + 1, s: st.s + 1, last: now }),
      { expirationTtl: 60 * 60 * 12 },
    ));

    // plan y credits: sin ellos la barra de créditos se congela en streaming,
    // porque el cliente solo los recibe en las respuestas no-stream de n8n.
    // ?? null y no || null: un plan '' o 0 créditos son valores legítimos que
    // hay que transmitir tal cual, no convertir en «desconocido».
    await send('meta', {
      router_empty: !!prep.router_empty,
      lang: prep.lang || lang,
      files: prep.files_count ?? 0,
      plan: prep.plan ?? null,
      credits: prep.credits ?? null,
      prestream_ms: Date.now() - t0,
    });
    await send('status', { stage: 'generating' });

    // ── Nota de KB faltante, EN PARALELO con Anthropic ─────────────────────
    // router_empty ya se sabe aquí, ANTES de llamar al modelo. Esperar la nota
    // en este punto pondría hasta diez segundos de pantalla muerta antes del
    // primer token, en el único módulo que streamea: el peor sitio posible.
    // Así que se dispara sin await y se recoge solo si el modelo abre con el
    // marcador. En el caso normal nadie la espera y se descarta; en el de hueco
    // el usuario paga únicamente lo que a PubMed le quede por terminar.
    //
    // La nota la compone hOq2KX1zxFjmFYak y SOLO ese workflow. Esto no compone
    // nada: pide y espera.
    let notaKB = null;
    const pedirNota = () => fetch(`${env.N8N_BASE}/internal-kbnote`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-internal-secret': env.N8N_INTERNAL_SECRET },
      body: JSON.stringify({
        procedure_id: proc.procedure_id,
        wavelength: proc.wavelength,
        // Respaldo para cuando no hay identificador (el chip "Otro"). Va en el
        // idioma del usuario, así que lo normal es que PubMed no encuentre nada
        // y salga la variante "sin resultados": fallar hacia el silencio es
        // exactamente lo que se quiere aquí.
        procedure_en: proc.procedure_other || proc.procedure_es,
        language: prep.lang || lang,
      }),
    }).then((r) => (r.ok ? r.json() : null)).catch(() => null);
    if (prep.router_empty) notaKB = pedirNota();

    // ── Anthropic. El payload llega INTACTO desde n8n: los dos breakpoints de
    //    cache_control van tal cual. El Worker no lo reescribe.
    const payload = { ...prep.payload, stream: true };
    const a = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-api-key': env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify(payload),
    });

    if (!a.ok || !a.body) {
      await send('error', { code: 502, message: `Anthropic respondió ${a.status}.` });
      return;
    }

    // ── Relé SSE con retención mínima para decidir el disclaimer ANTES de pintar.
    //    Solo se retienen los primeros KBMISS.length caracteres.
    let held = '';
    let decided = false;
    let trimming = false;   // tras quitar el marcador, come el salto de línea que lo sigue
                            // aunque llegue en un chunk POSTERIOR (el modelo puede trocear
                            // el marcador carácter a carácter).
    let suprimido = false;  // hueco de KB con nota: lo que el modelo siga escribiendo
                            // no se pinta. Un protocolo compuesto SIN KB validada es
                            // justo lo que el producto no puede enseñar.

    const flush = async (chunk) => {
      if (suprimido) return;
      if (decided) {
        if (trimming) {
          chunk = chunk.replace(/^\s+/, '');
          if (!chunk) return;
          trimming = false;
        }
        full += chunk; await send('delta', { text: chunk }); return;
      }
      held += chunk;
      if (held.length < KBMISS.length) return;        // aún no se puede decidir
      decided = true;
      if (held.startsWith(KBMISS)) {
        kbMiss = true;
        held = held.slice(KBMISS.length);
        trimming = true;
        held = held.replace(/^\s+/, '');
        if (held) trimming = false;
        await send('kb_miss', { lang: prep.lang || lang });

        // Se recoge la nota que ya venía en camino. Si el router NO vino vacío
        // no se pidió antes —el modelo marcó el hueco por su cuenta—, así que
        // se pide ahora y se paga entera: es el caso raro, no el normal.
        if (!notaKB) notaKB = pedirNota();
        const n = await notaKB;
        if (n) {
          // Se guardan aunque no haya nota utilizable: un hueco registrado sin
          // cita sigue siendo un dato útil.
          kbPmids = String(n.pmids == null ? '' : n.pmids);
          kbHits = Number(n.pubmed_hits) || 0;
          // El gap_key llega YA compuesto desde el subworkflow, con la tabla
          // inglesa de procedure_id. Aquí no se compone: si Protocols lo armara
          // por su cuenta con procedure_es y Validate con el texto del marcador,
          // el mismo hueco se contaría dos veces y el contador de demanda de la
          // KB quedaría partido entre idiomas.
          if (typeof n.gap_key === 'string' && n.gap_key.trim() && n.gap_key.trim() !== '|') {
            kbGapKey = n.gap_key.trim();
          }
        }
        if (n && typeof n.nota === 'string' && n.nota.trim()) {
          suprimido = true;
          held = '';
          full = n.nota.trim();
          await send('delta', { text: full });
          return;
        }
        // Sin nota se sigue como hasta hoy: se emite lo que el modelo escribió.
        // No es lo ideal, pero es el comportamiento que ya había y no se
        // empeora nada.
      }
      if (held) { full += held; await send('delta', { text: held }); held = ''; }
    };

    const reader = a.body.getReader();
    let buf = '';
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });

      let nl;
      while ((nl = buf.indexOf('\n\n')) >= 0) {
        const raw = buf.slice(0, nl); buf = buf.slice(nl + 2);
        const line = raw.split('\n').find((l) => l.startsWith('data:'));
        if (!line) continue;
        let ev;
        try { ev = JSON.parse(line.slice(5).trim()); } catch { continue; }

        if (ev.type === 'content_block_delta' && ev.delta?.type === 'text_delta') {
          await flush(ev.delta.text);
        } else if (ev.type === 'message_start') {
          usage = { ...usage, ...(ev.message?.usage || {}) };
        } else if (ev.type === 'message_delta') {
          usage = { ...usage, ...(ev.usage || {}) };
        } else if (ev.type === 'error') {
          await send('error', { code: 502, message: ev.error?.message || 'Error del modelo.' });
        }
        if (suprimido) break;
      }
      if (suprimido) break;
    }

    // ── Se cortó el grifo: ya se emitió la nota y lo que el modelo siga
    //    escribiendo no se va a pintar. Seguir leyendo para tirar dejaba la
    //    burbuja en estado «escribiendo» ~38 s después de que el usuario ya
    //    tuviera su texto, y encima pagando tokens de salida descartados.
    //    Medido antes del cambio: nota a los 5,8 s, `done` a los 43,6 s.
    //
    //    El `done` de más abajo se envía igual, así que el cliente cierra
    //    limpio y no ve un error. Y el finalize del `finally` tampoco se pierde:
    //    va por ctx.waitUntil, que sobrevive al cierre de la respuesta.
    //
    //    CONSECUENCIA ACEPTADA: al cancelar no llega el `message_delta` final,
    //    así que en estos turnos `output_tokens` queda incompleto. Es fiel a lo
    //    que pasó —se canceló— y el turno no cobra crédito de todos modos.
    if (suprimido) { try { await reader.cancel(); } catch {} }
    // Respuesta más corta que el marcador: decidir con lo que haya.
    if (!decided && held) { decided = true; full += held; await send('delta', { text: held }); }

    await send('done', { chars: full.length, kb_miss: kbMiss, total_ms: Date.now() - t0 });
  } catch (e) {
    try { await send('error', { code: 502, message: String(e).slice(0, 200) }); } catch {}
  } finally {
    try { await writer.close(); } catch {}

    // ── finalize SIEMPRE, incluso si el usuario cerró la pestaña. ctx.waitUntil
    //    mantiene viva la tarea tras cerrar la respuesta; sin esto se perderían
    //    consultas de Consultations y correos de KB miss en cada abandono.
    // EL CUERPO SE COMPONE FUERA DEL waitUntil, con su propio try. Antes se
    // componía dentro de la llamada, así que un error al componerlo se llevaba
    // por delante la llamada entera: un `let` fuera de ámbito dejó 17 minutos
    // sin una sola fila en Consultations, sin ruido de ninguna clase. Ahora un
    // fallo al componer DEGRADA el registro en vez de borrarlo — se manda lo
    // mínimo más el error, y queda a la vista en la propia fila.
    if (prep && !prep.error) {
      let cuerpo;
      try {
        cuerpo = JSON.stringify({
          email: claims.sub, query: q, response: full.slice(0, 30000),
          lang: prep.lang || lang, kb_miss: kbMiss, router_empty: !!prep.router_empty,
          usage, request_id: prep.request_id || null,
          module: mod || 'protocols',
          // Compuesto en el subworkflow, no aquí. Ver arriba.
          gap_key: kbMiss ? kbGapKey : '',
          pmids: kbPmids,
          pubmed_hits: kbHits,
        });
      } catch (e) {
        cuerpo = JSON.stringify({
          email: (claims && claims.sub) || '',
          query: String(q || '').slice(0, 4000),
          response: '[finalize_error] ' + String(e).slice(0, 200),
          lang: lang, kb_miss: false, router_empty: false,
          usage: {}, request_id: null, module: mod || 'protocols',
          gap_key: '', pmids: '', pubmed_hits: 0,
        });
      }
      ctx.waitUntil(
        fetch(`${env.N8N_BASE}/internal-finalize`, {
          method: 'POST',
          headers: { 'content-type': 'application/json', 'x-internal-secret': env.N8N_INTERNAL_SECRET },
          body: cuerpo,
        }).catch(() => {}),
      );
    }
  }
}
