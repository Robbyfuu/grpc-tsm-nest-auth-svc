import { Controller, UseGuards, Request } from '@nestjs/common';
import { AuthService } from './auth.service';
import { GrpcMethod } from '@nestjs/microservices';
import {
  AUTH_SERVICE_NAME,
  ForgotPasswordRequest,
  LoginResponse,
  RefreshTokenRequest,
  RefreshTokenResponse,
  RegisterResponse,
  ResetPasswordRequest,
  ValidateTokenResponse,
} from './auth.pb';
import { LoginRequestDto, RegisterRequestDto, ValidateRequestDto } from './dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) { }
  @GrpcMethod(AUTH_SERVICE_NAME, 'Register')
  private async register(
    payload: RegisterRequestDto,
  ): Promise<RegisterResponse> {
    const { email, nombre, password, role } = payload;
    return this.authService.register(email, nombre, password, role);
  }

  @GrpcMethod(AUTH_SERVICE_NAME, 'Login')
  private login(payload: LoginRequestDto): Promise<LoginResponse> {
    console.log('login');
    console.log(payload);
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
  @GrpcMethod(AUTH_SERVICE_NAME, 'ResetPassword')
  private resetPassword(payload: ResetPasswordRequest) {
    return this.authService.resetPassword(payload);
  }

  @GrpcMethod(AUTH_SERVICE_NAME, 'ForgotPassword')
  private forgotPassword(payload: ForgotPasswordRequest) {
    return this.authService.forgotPassword(payload);
  }
}
