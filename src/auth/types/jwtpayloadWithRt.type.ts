import { JwtPayload } from './jwtPayload.type';

export type jwtPayloadWithRT = JwtPayload & {
  refreshToken: string;
};
