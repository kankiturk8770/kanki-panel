// ==================================================================== start
// 3.68: a token kept by an older version is dropped; the cookie decides (boot shows the login on 401)
try{localStorage.removeItem('kk_tok')}catch(e){}
applyLook();boot();
