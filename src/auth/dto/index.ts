import { IsEmail, IsNotEmpty, IsString, IsOptional } from 'class-validator';
import { ValidateTokenRequest } from '../auth.pb';

export class LoginRequestDto {
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @IsString()
  @IsNotEmpty()
  password: string;
}

export class RegisterRequestDto {
  @IsString()
  @IsNotEmpty()
  nombre: string;

  @IsEmail()
  @IsNotEmpty()
  email: string;

  @IsString()
  @IsNotEmpty()
  password: string;

  @IsString()
  @IsNotEmpty()
  role: string;
}

export class ForgotPasswordRequestDto {
  @IsEmail()
  @IsNotEmpty()
  email: string;
}

export class ResetPasswordRequestDto {
  @IsString()
  @IsOptional()
  token: string;

  @IsString()
  @IsNotEmpty()
  password: string;
}

export class RefreshTokenRequestDto {
  @IsString()
  @IsNotEmpty()
  refreshToken: string;
}
export class ValidateRequestDto implements ValidateTokenRequest {
  @IsString()
  public readonly token: string;
}
