import {
  Injectable,
  Logger,
  HttpStatus,
  UnauthorizedException,
  UnprocessableEntityException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { MailerService } from '@nestjs-modules/mailer';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import { User } from './entities/user.entity';
import { RefreshToken } from './entities/refresh-token.entity';
import { TokenExpiredError, JwtPayload } from 'jsonwebtoken';
import { LoginRequestDto, ValidateRequestDto } from './dto';
import {
  ForgotPasswordRequest,
  ForgotPasswordResponse,
  LoginResponse,
  RefreshTokenResponse,
  RegisterResponse,
  ResetPasswordRequest,
  ResetPasswordResponse,
  ValidateTokenResponse,
} from './auth.pb';

@Injectable()
export class AuthService {
  logger = new Logger('AuthService');
  constructor(
    @InjectRepository(User)
    private readonly userModel: Repository<User>,
    private readonly jwtService: JwtService,
    @InjectRepository(RefreshToken)
    private readonly refreshTokenModel: Repository<RefreshToken>,
    private readonly mailerService: MailerService,
  ) {}

  async validateUserWithPassword(email: string, pass: string): Promise<User> {
    const user = await this.userModel.findOne({ where: { email } });
    if (user) {
      if (!user.estado) {
        throw new UnauthorizedException(`User is inactive, talk with an admin`);
      }
      const { password } = user;
      const match = await bcrypt.compareSync(pass, password);
      delete user.password;
      if (match) {
        return user;
      }
    }
    return null;
  }
  async generateAccessToken(user: User) {
    const payload = { sub: String(user.id) };
    return await this.jwtService.signAsync(payload);
  }

  async createRefreshToken(user: User, ttl: number) {
    const expiration = new Date();
    expiration.setTime(expiration.getTime() + ttl);

    const token = new RefreshToken();
    token.user = user;
    token.expires = expiration;
    await this.refreshTokenModel.save(token);

    return token;
  }

  async generateRefreshToken(user: User, expiresIn: number) {
    const payload = { sub: String(user.id) };
    const token = await this.createRefreshToken(user, expiresIn);
    return await this.jwtService.signAsync(
      { ...payload, expiresIn, jwtId: String(token.id) },
      { expiresIn: '7d' },
    );
  }

  async resolveRefreshToken(encoded: string) {
    try {
      const payload: JwtPayload = await this.jwtService.verify(encoded);
      this.logger.log(payload);
      if (!payload.sub || !payload.jwtId) {
        throw new UnprocessableEntityException('Refresh token malformed');
      }
      const token = await this.refreshTokenModel.findOneBy({
        id: payload.jwtId,
      });
      this.logger.log(token);

      if (!token) {
        throw new UnprocessableEntityException('Refresh token not found');
      }

      if (token.revoked) {
        throw new UnprocessableEntityException('Refresh token revoked');
      }

      const user = await this.userModel.findOneBy({
        id: parseInt(payload.sub),
      });

      // const user = await this.userModel.findOneBy({ id: payload.sub });
      this.logger.log(user);
      if (!user) {
        throw new UnprocessableEntityException('Refresh token malformed');
      }

      return { user, token };
    } catch (e) {
      if (e instanceof TokenExpiredError) {
        throw new UnprocessableEntityException('Refresh token expired');
      } else {
        throw new UnprocessableEntityException('Refresh token malformed');
      }
    }
  }
  async getUserFromToken(token: string): Promise<User> {
    const payload = await this.jwtService.verify(token);
    const user = await this.userModel.findOneBy({ id: payload.sub });
    if (!user) {
      throw new UnprocessableEntityException('Refresh token malformed');
    }

    return user;
  }

  async createAccessTokenFromRefreshToken(
    refresh: string,
  ): Promise<RefreshTokenResponse> {
    const { user } = await this.resolveRefreshToken(refresh);

    const token = await this.generateAccessToken(user);

    const refreshToken = await this.generateRefreshToken(
      user,
      12 * 60 * 60 * 1000,
    );

    return {
      ok: true,
      status: HttpStatus.OK,
      usuario: user,
      token,
      refreshToken,
    };
  }

  async register(
    email: string,
    nombre: string,
    password: string,
    role?: string,
  ): Promise<RegisterResponse> {
    const user = await this.userModel.findOne({ where: { email } });
    if (user) {
      // error user already exists
      return {
        ok: false,
        status: HttpStatus.CONFLICT,
        error: 'User already exists',
      };
    }
    try {
      const newUser = new User();
      newUser.email = email;
      newUser.nombre = nombre;
      newUser.role = role;
      newUser.password = bcrypt.hashSync(password, 10);

      await this.userModel.save(newUser);
      const token = await this.generateAccessToken(newUser);
      const refreshToken = await this.generateRefreshToken(
        newUser,
        12 * 60 * 60 * 1000,
      );

      return {
        ok: true,
        status: HttpStatus.CREATED,
        usuario: {
          ...newUser,
          createdAt: {
            seconds: newUser.createdAt.getTime() / 1000,
            nanos: (newUser.createdAt.getTime() % 1000) * 1e6,
          },
          updatedAt: {
            seconds: newUser.updatedAt.getTime() / 1000,
            nanos: (newUser.updatedAt.getTime() % 1000) * 1e6,
          },
        },
        token,
        refreshToken,
      };
    } catch (error) {
      this.logger.error(error);
      return {
        ok: false,
        status: HttpStatus.INTERNAL_SERVER_ERROR,
        error: 'Internal server error',
      };
    }
  }
  async login(loginInput: LoginRequestDto): Promise<LoginResponse> {
    const { email, password } = loginInput;
    const user = await this.userModel.findOne({ where: { email } });
    if (!user) {
      return {
        ok: false,
        status: HttpStatus.UNPROCESSABLE_ENTITY,
        error: 'Invalid credentials',
      };
    }
    if (!bcrypt.compareSync(password, user.password)) {
      return {
        ok: false,
        status: HttpStatus.UNPROCESSABLE_ENTITY,
        error: 'Invalid credentials',
      };
    }
    return {
      ok: true,
      status: HttpStatus.OK,
      usuario: {
        ...user,
        createdAt: {
          seconds: user.createdAt.getTime() / 1000,
          nanos: (user.createdAt.getTime() % 1000) * 1e6,
        },
        updatedAt: {
          seconds: user.updatedAt.getTime() / 1000,
          nanos: (user.updatedAt.getTime() % 1000) * 1e6,
        },
      },
      token: await this.generateAccessToken(user),
      refreshToken: await this.generateRefreshToken(user, 12 * 60 * 60 * 1000),
    };
  }
  async loginRefresh(user: any) {
    const payload = { email: user.email, sub: user.userId };
    return {
      access_token: this.jwtService.sign(payload),
    };
  }

  async validateToken({
    token,
  }: ValidateRequestDto): Promise<ValidateTokenResponse> {
    const decoded = await this.jwtService.verify(token);

    if (!decoded) {
      return {
        status: HttpStatus.FORBIDDEN,
        error: ['Token is invalid'],
        user: null,
      };
    }

    const auth: User = await this.validateUser(decoded);

    if (!auth) {
      return {
        status: HttpStatus.CONFLICT,
        error: ['User not found'],
        user: null,
      };
    }

    return {
      status: HttpStatus.OK,
      error: null,
      user: {
        ...auth,
        createdAt: {
          seconds: auth.createdAt.getTime() / 1000,
          nanos: (auth.createdAt.getTime() % 1000) * 1e6,
        },
        updatedAt: {
          seconds: auth.updatedAt.getTime() / 1000,
          nanos: (auth.updatedAt.getTime() % 1000) * 1e6,
        },
      },
    };
  }
  private async validateUser(decoded: any): Promise<User> {
    const user = await this.userModel.findOneBy({ id: decoded.sub });

    if (!user.estado) {
      throw new UnauthorizedException(`User is inactive, talk with an admin`);
    }
    return user;
  }
  async resetPassword(
    payload: ResetPasswordRequest,
  ): Promise<ResetPasswordResponse> {
    const { token, password } = payload;
    const decoded = await this.jwtService.verify(token);
    const user = await this.validateUser(decoded);
    if (!user) {
      return {
        ok: false,
        status: HttpStatus.CONFLICT,
        msg: 'User not found',
        usuario: null,
      };
    }
    user.password = bcrypt.hashSync(password, 10);
    await this.userModel.save(user);
    return {
      ok: true,
      status: HttpStatus.OK,
      msg: 'Password changed',
      usuario: {
        ...user,
        createdAt: {
          seconds: user.createdAt.getTime() / 1000,
          nanos: (user.createdAt.getTime() % 1000) * 1e6,
        },
        updatedAt: {
          seconds: user.updatedAt.getTime() / 1000,
          nanos: (user.updatedAt.getTime() % 1000) * 1e6,
        },
      },
    };
  }
  async forgotPassword(
    payload: ForgotPasswordRequest,
  ): Promise<ForgotPasswordResponse> {
    const { email } = payload;
    const user = await this.userModel.findOne({ where: { email } });
    if (!user) {
      return {
        ok: false,
        status: HttpStatus.CONFLICT,
        msg: 'User not found',
        usuario: null,
      };
    }
    const token = await this.generateAccessToken(user);
    const url = `https://tsm-admin.cl/reset-password?${token}`;

    return await this.mailerService
      .sendMail({
        to: email,
        subject: 'Recuperar contraseña',
        template: './resetpass',
        context: {
          url,
        },
        attachments: [
          {
            filename: 'image-1.png',
            path: './src/shared/mailer/templates/images/image-1.png',
            cid: 'imagen-1',
          },
          {
            filename: 'image-2.png',
            path: './src/shared/mailer/templates/images/image-2.png',
            cid: 'image-2',
          },
          {
            filename: 'image-3.png',
            path: './src/shared/mailer/templates/images/image-3.png',
            cid: 'image-3',
          },
          {
            filename: 'image-4.png',
            path: './src/shared/mailer/templates/images/image-4.png',
            cid: 'image-4',
          },
          {
            filename: 'image-5.png',
            path: './src/shared/mailer/templates/images/image-5.png',
            cid: 'image-5',
          },
          {
            filename: 'logoTSM1.png',
            path: './src/shared/mailer/templates/images/logoTSM1.png',
            cid: 'logoTSM1',
          },
        ],
      })
      .then((res) => {
        return {
          ok: true,
          status: HttpStatus.OK,
          msg: 'Email sent',
          usuario: {
            ...user,
            createdAt: {
              seconds: user.createdAt.getTime() / 1000,
              nanos: (user.createdAt.getTime() % 1000) * 1e6,
            },
            updatedAt: {
              seconds: user.updatedAt.getTime() / 1000,
              nanos: (user.updatedAt.getTime() % 1000) * 1e6,
            },
          },
        };
      })
      .catch((error) => {
        this.logger.error(error);
        return {
          ok: false,
          status: HttpStatus.INTERNAL_SERVER_ERROR,
          msg: error,
          usuario: null,
        };
      });
  }
}
