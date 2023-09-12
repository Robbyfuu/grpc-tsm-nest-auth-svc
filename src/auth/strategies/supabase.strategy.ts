// import { Injectable } from '@nestjs/common';
// import { PassportStrategy } from '@nestjs/passport';
// import { ExtractJwt } from 'passport-jwt';
// import { SupabaseAuthStrategy } from 'nestjs-supabase-auth';
// import { ConfigService } from '@nestjs/config';

// @Injectable()
// export class SupabaseStrategy extends PassportStrategy(
//   SupabaseAuthStrategy,
//   'supabase',
// ) {
//   public constructor(configService: ConfigService) {
//     super({
//       supabaseUrl: configService.get<string>('auth.supaUrl'),
//       supabaseKey: configService.get<string>('auth.supaKey'),
//       supabaseOptions: {},
//       supabaseJwtSecret: configService.get<string>('auth.jwtKey'),
//       extractor: ExtractJwt.fromAuthHeaderAsBearerToken(),
//     });
//   }

//   async validate(payload: any): Promise<any> {
//     super.validate(payload);
//   }

//   authenticate(req) {
//     super.authenticate(req);
//   }
// }
