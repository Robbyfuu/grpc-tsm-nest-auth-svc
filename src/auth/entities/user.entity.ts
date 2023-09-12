import {
  BaseEntity,
  Column,
  CreateDateColumn,
  Entity,
  OneToMany,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';
import { RefreshToken } from './refresh-token.entity';

@Entity()
export class User extends BaseEntity {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ type: 'varchar', length: 255, nullable: false })
  nombre: string;

  @Column({ type: 'varchar', length: 255, nullable: false })
  email: string;

  @Column({ type: 'boolean', default: true })
  estado: boolean;

  @Column({ type: 'varchar', length: 255, nullable: true })
  password: string;

  @Column({
    type: 'enum',
    enum: ['ADMIN_ROLE', 'USER_ROLE'],
    default: 'USER_ROLE',
  })
  role: string;

  @OneToMany(() => RefreshToken, (refreshToken) => refreshToken.user)
  refreshTokens: RefreshToken;

  @CreateDateColumn({ type: 'timestamp' })
  public createdAt!: Date;
  @UpdateDateColumn({ type: 'timestamp' })
  public updatedAt!: Date;
}
