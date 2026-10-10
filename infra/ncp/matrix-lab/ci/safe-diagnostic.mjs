// Never emit error messages, stacks, keys, tokens or arbitrary child IPC fields.
const operations=new Set(['start','verify','create','join','ready','send','decrypt','redact','deleted','stop']);
const kinds=new Set(['Error','TypeError','MatrixError','HTTPError','Other']);
const codes=new Set(['M_BAD_JSON','M_INVALID_PARAM','M_FORBIDDEN','M_UNKNOWN','M_NOT_FOUND','M_UNRECOGNIZED','M_UNKNOWN_TOKEN','M_LIMIT_EXCEEDED','ECONNREFUSED','ETIMEDOUT']);
export function safeDiagnostic(d){
 return {operation:operations.has(d?.operation)?d.operation:'OTHER',kind:kinds.has(d?.kind)?d.kind:'Other',code:codes.has(d?.code)?d.code:'OTHER',httpStatus:Number.isInteger(d?.httpStatus)&&d.httpStatus>=100&&d.httpStatus<=599?d.httpStatus:null};
}
