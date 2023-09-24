import { join } from 'path';
import { NestFactory } from '@nestjs/core';
import { Transport } from '@nestjs/microservices';
import { INestMicroservice, ValidationPipe } from '@nestjs/common';
import { AppModule } from './app.module';
import { protobufPackage } from './auth/auth.pb';
import { HttpExceptionFilter } from '@/common/helpers/http-exception.helper';

async function bootstrap() {
  const app: INestMicroservice = await NestFactory.createMicroservice(
    AppModule,
    {
      transport: Transport.GRPC,
      options: {
        url: `${process.env.GRPC_SERVER_HOST}:50051`,
        package: protobufPackage,
        protoPath: join('node_modules/grpc-tsm-nestjs-proto/proto/auth.proto'),
      },
    },
  );
  console.log(`gRPC server running on ${process.env.GRPC_SERVER_HOST}:50051`);
  app.useGlobalFilters(new HttpExceptionFilter());
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
