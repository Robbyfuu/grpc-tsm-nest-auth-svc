import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  ManyToOne,
  UpdateDateColumn,
} from 'typeorm';
import { User } from './user.entity';

@Entity()
export class RefreshToken {
  @PrimaryGeneratedColumn('uuid')
  public id: string;
  @ManyToOne(() => User, (user) => user.refreshTokens)
  public user: User;
  @Column({ type: 'boolean', default: false })
  public revoked;
  @Column()
  public expires: Date;
  @CreateDateColumn()
  public createdAt: Date;
  @UpdateDateColumn()
  public updatedAt: Date;
}
