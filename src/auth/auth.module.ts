import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { AtStrategy, RtStrategy } from './strategies';
import { JwtService } from '@nestjs/jwt';

@Module({
  providers: [AuthService, RtStrategy, AtStrategy, JwtService],
  controllers: [AuthController],
})
export class AuthModule {}
