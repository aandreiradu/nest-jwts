import { ExecutionContext, createParamDecorator } from '@nestjs/common';
import { jwtPayloadWithRT } from 'src/auth/types';

export const GetCurrentUser = createParamDecorator(
  (data: keyof jwtPayloadWithRT | undefined, context: ExecutionContext) => {
    const request = context.switchToHttp().getRequest();

    if (!data) return request.user;
    return request.user[data];
  },
);
