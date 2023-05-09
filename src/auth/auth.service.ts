import {
  ForbiddenException,
  Injectable,
  InternalServerErrorException,
} from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDTO } from './dto';
import * as argon from 'argon2';
import { Tokens } from './types';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private config: ConfigService,
  ) {}

  async signUpLocal(dto: AuthDTO): Promise<Tokens> {
    const hash = await this.hashData(dto.password);

    const user = await this.prisma.user.create({
      data: {
        email: dto.email,
        hash: hash,
      },
    });

    const tokens = await this.generateAuthTokens(user.id, user.email);
    await this.updateRtHash(user.id, tokens.refresh_token);
    return tokens;
  }

  async signInLocal(dto: AuthDTO): Promise<Tokens> {
    const user = await this.prisma.user.findFirst({
      where: {
        email: dto.email,
      },
    });

    if (!user) {
      throw new ForbiddenException('Invalid credentials');
    }

    const passwordMatch = await argon.verify(user.hash, dto.password);

    if (!passwordMatch) {
      throw new ForbiddenException('Invalid credentials');
    }

    const tokens = await this.generateAuthTokens(user.id, user.email);
    await this.updateRtHash(user.id, tokens.refresh_token);
    return tokens;
  }

  async logout(userId: string) {
    await this.prisma.user.updateMany({
      where: {
        id: userId,
        hashRT: {
          not: null,
        },
      },
      data: {
        hashRT: null,
      },
    });
  }

  async refreshTokens(userId: string, rt: string) {
    const user = await this.prisma.user.findFirst({
      where: {
        id: userId,
      },
    });

    if (!user || !user.hashRT) {
      console.log('no user found');
      throw new ForbiddenException('Access denied');
    }

    const rtMatches = await argon.verify(user.hashRT, rt);

    if (!rtMatches) {
      console.log('rt dont match');
      throw new ForbiddenException('Access denied');
    }

    const tokens = await this.generateAuthTokens(user.id, user.email);
    await this.updateRtHash(user.id, tokens.refresh_token);
    return tokens;
  }

  async hashData(data: string) {
    return await argon.hash(data);
  }

  async generateAuthTokens(userId: string, email: string): Promise<Tokens> {
    const [rt, at] = await Promise.all([
      this.jwtService.signAsync(
        {
          sub: userId,
          email,
        },
        {
          secret: this.config.get('JWT_RT_SECRET'),
          expiresIn: 60 * 60 * 24 * 7,
        },
      ),
      this.jwtService.signAsync(
        {
          sub: userId,
          email,
        },
        {
          secret: this.config.get('JWT_AT_SECRET'),
          expiresIn: 60 * 15,
        },
      ),
    ]);

    return {
      access_token: at,
      refresh_token: rt,
    };
  }

  async updateRtHash(userId: string, rt: string) {
    const hash = await this.hashData(rt);

    await this.prisma.user.update({
      where: {
        id: userId,
      },
      data: {
        hashRT: hash,
      },
    });
  }
}
