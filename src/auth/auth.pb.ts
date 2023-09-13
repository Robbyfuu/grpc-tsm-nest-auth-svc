/* eslint-disable */
import { GrpcMethod, GrpcStreamMethod } from "@nestjs/microservices";
import { Observable } from "rxjs";

export const protobufPackage = "auth";

export interface User {
  id: number;
  nombre: string;
  email: string;
  estado: boolean;
  password: string;
  role: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface LoginRequest {
  email: string;
  password: string;
}

export interface LoginResponse {
  ok: boolean;
  status: number;
  usuario?: User | undefined;
  token?: string | undefined;
  refreshToken?: string | undefined;
  error?: string | undefined;
}

export interface RegisterRequest {
  nombre: string;
  email: string;
  password: string;
  role: string;
}

export interface RegisterResponse {
  ok: boolean;
  status: number;
  usuario?: User | undefined;
  token?: string | undefined;
  refreshToken?: string | undefined;
  error?: string | undefined;
}

export interface ForgotPasswordRequest {
  email: string;
}

export interface ForgotPasswordResponse {
  ok: boolean;
  status: number;
  msg: string;
  usuario: User | undefined;
}

export interface ResetPasswordRequest {
  token: string;
  password: string;
}

export interface ResetPasswordResponse {
  ok: boolean;
  status: number;
  msg: string;
  usuario: User | undefined;
}

export interface RefreshTokenRequest {
  refreshToken: string;
}

export interface RefreshTokenResponse {
  ok: boolean;
  status: number;
  usuario: User | undefined;
  token: string;
  refreshToken: string;
}

export interface ValidateTokenRequest {
  token: string;
}

export interface ValidateTokenResponse {
  status: number;
  error: string[];
  userId: number;
}

export const AUTH_PACKAGE_NAME = "auth";

export interface AuthServiceClient {
  login(request: LoginRequest): Observable<LoginResponse>;

  register(request: RegisterRequest): Observable<RegisterResponse>;

  validateToken(request: ValidateTokenRequest): Observable<ValidateTokenResponse>;

  forgotPassword(request: ForgotPasswordRequest): Observable<ForgotPasswordResponse>;

  resetPassword(request: ResetPasswordRequest): Observable<ResetPasswordResponse>;

  refreshToken(request: RefreshTokenRequest): Observable<RefreshTokenResponse>;
}

export interface AuthServiceController {
  login(request: LoginRequest): Promise<LoginResponse> | Observable<LoginResponse> | LoginResponse;

  register(request: RegisterRequest): Promise<RegisterResponse> | Observable<RegisterResponse> | RegisterResponse;

  validateToken(
    request: ValidateTokenRequest,
  ): Promise<ValidateTokenResponse> | Observable<ValidateTokenResponse> | ValidateTokenResponse;

  forgotPassword(
    request: ForgotPasswordRequest,
  ): Promise<ForgotPasswordResponse> | Observable<ForgotPasswordResponse> | ForgotPasswordResponse;

  resetPassword(
    request: ResetPasswordRequest,
  ): Promise<ResetPasswordResponse> | Observable<ResetPasswordResponse> | ResetPasswordResponse;

  refreshToken(
    request: RefreshTokenRequest,
  ): Promise<RefreshTokenResponse> | Observable<RefreshTokenResponse> | RefreshTokenResponse;
}

export function AuthServiceControllerMethods() {
  return function (constructor: Function) {
    const grpcMethods: string[] = [
      "login",
      "register",
      "validateToken",
      "forgotPassword",
      "resetPassword",
      "refreshToken",
    ];
    for (const method of grpcMethods) {
      const descriptor: any = Reflect.getOwnPropertyDescriptor(constructor.prototype, method);
      GrpcMethod("AuthService", method)(constructor.prototype[method], method, descriptor);
    }
    const grpcStreamMethods: string[] = [];
    for (const method of grpcStreamMethods) {
      const descriptor: any = Reflect.getOwnPropertyDescriptor(constructor.prototype, method);
      GrpcStreamMethod("AuthService", method)(constructor.prototype[method], method, descriptor);
    }
  };
}

export const AUTH_SERVICE_NAME = "AuthService";
