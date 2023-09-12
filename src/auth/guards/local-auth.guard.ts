import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class LocalAuthGuard extends AuthGuard('local') {
  //   async canActivate(context: ExecutionContext): Promise<boolean> {
  //     // Ejecuta el método canActivate original de la clase base
  //     const result = (await super.canActivate(context)) as boolean;
  //     // Añade tu lógica personalizada aquí
  //     // ...
  //     // Retorna true para permitir acceso, o false para denegarlo
  //     return result;
  //   }
  //   handleRequest(err, user, info: Error) {
  //     // Puedes lanzar una excepción personalizada
  //     if (err || !user) {
  //       throw err || new UnauthorizedException(info.message);
  //     }
  //     // Puedes también personalizar la respuesta en este punto si es necesario
  //     return user;
  //   }
}
