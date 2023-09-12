import { Controller, UseGuards, Request } from '@nestjs/common';
import { AuthService } from './auth.service';
import { GrpcMethod } from '@nestjs/microservices';
import { AUTH_SERVICE_NAME, LoginResponse, RegisterResponse } from './auth.pb';
import { LoginRequestDto, RegisterRequestDto } from './dto';
import { LocalAuthGuard } from './guards';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}
  @GrpcMethod(AUTH_SERVICE_NAME, 'Register')
  private register(payload: RegisterRequestDto): Promise<RegisterResponse> {
    const { email, nombre, password, role } = payload;
    return this.authService.register(email, nombre, password, role);
    
  }
  // @UseGuards(LocalAuthGuard)
  @GrpcMethod(AUTH_SERVICE_NAME, 'Login')
  private login(@Request() req ,payload: LoginRequestDto): Promise<LoginResponse> {
    // console.log(req.user)
    return this.authService.login(payload);
  }
}
