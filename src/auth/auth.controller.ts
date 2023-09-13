import { Controller, UseGuards, Request } from '@nestjs/common';
import { AuthService } from './auth.service';
import { GrpcMethod } from '@nestjs/microservices';
import {
  AUTH_SERVICE_NAME,
  LoginResponse,
  RefreshTokenRequest,
  RefreshTokenResponse,
  RegisterResponse,
  ValidateTokenResponse,
} from './auth.pb';
import { LoginRequestDto, RegisterRequestDto, ValidateRequestDto } from './dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}
  @GrpcMethod(AUTH_SERVICE_NAME, 'Register')
  private register(payload: RegisterRequestDto): Promise<RegisterResponse> {
    const { email, nombre, password, role } = payload;
    return this.authService.register(email, nombre, password, role);
  }

  @GrpcMethod(AUTH_SERVICE_NAME, 'Login')
  private login(payload: LoginRequestDto): Promise<LoginResponse> {
    return this.authService.login(payload);
  }

  @GrpcMethod(AUTH_SERVICE_NAME, 'RefreshToken')
  private refreshToken({
    refreshToken,
  }: RefreshTokenRequest): Promise<RefreshTokenResponse> {
    return this.authService.createAccessTokenFromRefreshToken(refreshToken);
  }
  @GrpcMethod(AUTH_SERVICE_NAME, 'ValidateToken')
  private validateToken(
    payload: ValidateRequestDto,
  ): Promise<ValidateTokenResponse> {
    return this.authService.validateToken(payload);
  }
}
