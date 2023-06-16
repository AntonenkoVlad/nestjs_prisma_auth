import { MailerService } from '@nestjs-modules/mailer';
import { Injectable } from '@nestjs/common';

@Injectable()
export class MailService {
  constructor(private mailerService: MailerService) {}

  async sendVerifyEmail(email: string, name: string, link: string) {
    try {
      await this.mailerService.sendMail({
        to: email,
        subject: 'Verify Your Email',
        template: 'verifyEmail',
        context: {
          name: name,
          link,
        },
      });
    } catch (error) {
      console.log(error);
    }
  }

  async sendResetPasswordEmail(email: string, link: string) {
    try {
      await this.mailerService.sendMail({
        to: email,
        subject: 'Change Your Password',
        template: 'resetPasswordEmail',
        context: {
          link,
        },
      });
    } catch (error) {
      console.log(error);
    }
  }
}
