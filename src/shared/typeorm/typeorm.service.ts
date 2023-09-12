import { Injectable, Inject } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { TypeOrmOptionsFactory, TypeOrmModuleOptions } from '@nestjs/typeorm';
@Injectable()
export class TypeOrmConfigService implements TypeOrmOptionsFactory {
  @Inject(ConfigService)
  private readonly config: ConfigService;

  public createTypeOrmOptions(): TypeOrmModuleOptions {
    const dbType = this.config.get<string | undefined>('db.type');

    if (dbType === 'postgres') {
      return {
        type: 'postgres',
        host: this.config.get<string>('db.host'),
        port: this.config.get<number>('db.port'),
        database: this.config.get<string>('db.database'),
        username: this.config.get<string>('db.username'),
        password: this.config.get<string>('db.password'),
        entities: ['dist/**/*.entity.{ts,js}'],
        migrations: ['dist/migrations/*.{ts,js}'],
        migrationsTableName: 'typeorm_migrations',
        autoLoadEntities: true,
        logger: 'file',
        synchronize: this.config.get<boolean>('db.synchronize'), // never use TRUE in production!
      };
    } else if (dbType === 'mysql') {
      return {
        type: 'mysql',
        host: this.config.get<string>('db.host'),
        port: this.config.get<number>('db.port'),
        database: this.config.get<string>('db.database'),
        username: this.config.get<string>('db.username'),
        password: this.config.get<string>('db.password'),
        entities: ['dist/**/*.entity.{ts,js}'],
        migrations: ['dist/migrations/*.{ts,js}'],
        migrationsTableName: 'typeorm_migrations',
        autoLoadEntities: true,
        logger: 'file',
        synchronize: this.config.get<boolean>('db.synchronize'), // never use TRUE in production!
      };
    }
  }
}
