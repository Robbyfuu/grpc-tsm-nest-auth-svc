import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { getEnvPath } from './common/helpers/env.helper';
import { ConfigModule } from '@nestjs/config';
import configuration from './config/configuration';
import { TypeOrmConfigService } from './shared/typeorm/typeorm.service';
import { TypeOrmModule } from '@nestjs/typeorm';

const envFilePath: string = getEnvPath(`${__dirname}/common/env`);

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath,
      load: [configuration],
    }),
    TypeOrmModule.forRootAsync({
      useClass: TypeOrmConfigService,
    }),
    AuthModule,
  ],
  controllers: [AppController],
  providers: [AppService, TypeOrmConfigService],
})
export class AppModule {}
