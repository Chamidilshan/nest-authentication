import { Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectDataSource, InjectRepository } from '@nestjs/typeorm';
import { User } from 'src/users/entities/user.entity';
import { Repository } from 'typeorm';
import { HashingService } from '../hashing/hashing.service';
import { SignUpDto } from './dto/sign-up.dto/sign-up.dto';
import { SignInDto } from './dto/sign-in.dto/sign-in.dto';
import { JwtService } from '@nestjs/jwt';
import jwtConfig from '../config/jwt.config';
import { ConfigType } from '@nestjs/config';

@Injectable()
export class AuthenticationService {

    constructor(
        @InjectRepository(User) private readonly usersRepository: Repository<User>,
        private readonly hashingService: HashingService,
        private readonly jwtService: JwtService,
        @Inject(jwtConfig.KEY)
        private readonly jwtConfiguration: ConfigType<typeof jwtConfig>,
    ) {}

    async signUp(signUpDto: SignUpDto){
        try{
            const user= new User();
            user.email= signUpDto.email;
            user.password= await this.hashingService.hash(signUpDto.password);

            await this.usersRepository.save(user);
        }catch(e){
            throw new Error(e);
        }
    }

    async signIn(signInDto: SignInDto){
        try{
            const user= await this.usersRepository.findOneBy({email: signInDto.email });
            if(!user){
                throw new Error('User not found');
            }

            const isPasswordValid= await this.hashingService.compare(signInDto.password, user.password);
            if(!isPasswordValid){
                throw new UnauthorizedException('Invalid password');     
            }
            
            const accessToken = await this.jwtService.signAsync(
                {
                    sub: user.id,
                    email: user.email,
                },
                {
                    audience: this.jwtConfiguration.audience,
                    issuer: this.jwtConfiguration.issuer,
                    secret: this.jwtConfiguration.secret,
                    expiresIn: this.jwtConfiguration.accessTokenTtl 
                }
            )
            
        
            return { accessToken };


        }catch(e){ 
            throw new Error(e);
        }
    }

}
