import {
  Injectable,
  Logger,
  HttpStatus,
  UnauthorizedException,
  UnprocessableEntityException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import { User } from './entities/user.entity';
import { RefreshToken } from './entities/refresh-token.entity';
import { TokenExpiredError, JwtPayload } from 'jsonwebtoken';
import { LoginRequestDto, RegisterRequestDto } from './dto';
import { LoginResponse, RegisterResponse } from './auth.pb';

@Injectable()
export class AuthService {
  logger = new Logger('AuthService');
  constructor(
    @InjectRepository(User)
    private readonly userModel: Repository<User>,
    private readonly jwtService: JwtService,
    @InjectRepository(RefreshToken)
    private readonly refreshTokenModel: Repository<RefreshToken>,
  ) {}

  async validateUser(id: number): Promise<User> {
    const user = await this.userModel.findOneBy({ id });

    if (!user.estado) {
      throw new UnauthorizedException(`User is inactive, talk with an admin`);
    }
    return user;
  }
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

  async createAccessTokenFromRefreshToken(refresh: string) {
    const { user } = await this.resolveRefreshToken(refresh);

    const token = await this.generateAccessToken(user);

    const refreshToken = await this.generateRefreshToken(
      user,
      12 * 60 * 60 * 1000,
    );

    return { user, token, refreshToken };
  }

  async register(
    email: string,
    nombre: string,
    password: string,
    role?: string,
  ): Promise<RegisterResponse> {
    console.log({ email, password, role, nombre });
    const user = await this.userModel.findOne({ where: { email } });
    if (user) {
      // error user already exists
      return {
        ok: false,
        status: HttpStatus.CONFLICT,
        error: ['User already exists'],
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
      console.log({ newUser });
      return {
        ok: true,
        status: HttpStatus.CREATED,
        usuario: newUser,
        token,
        refreshToken,
      };
    } catch (error) {
      this.logger.error(error);
      return {
        ok: false,
        status: HttpStatus.INTERNAL_SERVER_ERROR,
        error: ['Internal server error'],
      };
    }
  }
  async login(loginInput: LoginRequestDto): Promise<LoginResponse> {
    console.log({ loginInput })
    const { email, password } = loginInput;
    const user = await this.userModel.findOne({ where: { email } });
    if (!user) {
      return {
        ok: false,
        status: HttpStatus.UNPROCESSABLE_ENTITY,
        error: ['Invalid credentials'],
      }
    }
    if (!bcrypt.compareSync(password, user.password)) {
      return {
        ok: false,
        status: HttpStatus.UNPROCESSABLE_ENTITY,
        error: ['Invalid credentials'],
      }
    }
    return {
      ok: true,
      status: HttpStatus.OK,
      usuario: user,
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
}
