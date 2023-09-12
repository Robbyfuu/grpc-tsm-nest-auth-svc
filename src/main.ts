import { NestFactory } from '@nestjs/core';
import { Transport } from '@nestjs/microservices';
import { AppModule } from './app.module';
import { INestMicroservice, ValidationPipe } from '@nestjs/common';
import { protobufPackage } from './auth/auth.pb';
import { join } from 'path';

async function bootstrap() {
  const app: INestMicroservice = await NestFactory.createMicroservice(
    AppModule,
    {
      transport: Transport.GRPC,
      options: {
        url: '0.0.0.0:50051',
        package: protobufPackage,
        protoPath: join('node_modules/grpc-tsm-nestjs-proto/proto/auth.proto'),
      },
    },
  );
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );
  await app.listen();
}
bootstrap();
