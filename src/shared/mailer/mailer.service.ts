import { Injectable, Inject } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { MailerOptionsFactory, MailerOptions } from '@nestjs-modules/mailer';
import { join } from 'path';
import { HandlebarsAdapter } from '@nestjs-modules/mailer/dist/adapters/handlebars.adapter';

@Injectable()
export class MailerConfigService implements MailerOptionsFactory {
  @Inject(ConfigService)
  private readonly config: ConfigService;

  public createMailerOptions(): MailerOptions {
    return {
      transport: {
        host: this.config.get<string>('mailer.host'),
        port: 587,
        secure: false,
        auth: {
          user: this.config.get<string>('mailer.user'),
          pass: this.config.get<string>('mailer.password'),
        },
      },
      defaults: {
        from: 'TSM Ayuda<tsm@tsm-admin.cl>',
      },
      template: {
        dir: join(__dirname, 'templates'),
        adapter: new HandlebarsAdapter(), // or new PugAdapter() or new EjsAdapter()
        options: {
          strict: true,
        },
      },
    };
  }
}
