import {Resolver, Query, Mutation, Arg, ObjectType, Field, Ctx, UseMiddleware, Int} from "type-graphql";
import {User} from "./entity/User";
import {compare, hash} from 'bcryptjs';
import {MyContext} from "./MyContext";
import {createAccessToken, createRefreshToken} from "./auth";
import {isAuth} from "./isAuth";
import {sendRefreshToken} from "./sendRefreshToken";
import {getConnection} from "typeorm";
import {verify} from "jsonwebtoken";

@ObjectType()
class LoginResponse {
    @Field()
    accessToken: string;
    @Field(() => User)
    user: User;
}

@Resolver()
export class UserResolver {
    @Query(() => String)
    hello() {
        return 'hi!';
    }

    @Query(() => String)
    @UseMiddleware(isAuth)
    bye(
        @Ctx() {payload}: MyContext
    ) {
        return `Your user ID is: ${payload!.userId}`;
    }

    @Query(() => [User])
    users() {
        return User.find();
    }

    @Query(() => User, { nullable: true })
    me(
        @Ctx() context: MyContext
    ) {
        const authorization = context.req.headers['authorization'];

        if (!authorization) {
            return null;
        }

        try {
            const token = authorization.split(' ')[1];
            const payload: any = verify(token, process.env.ACCESS_TOKEN_SECRET!);
            return User.findOne(payload.userId);
        } catch(err) {
            return null;
        }
    }

    @Mutation(() => Boolean)
    async register(
        @Arg('email') email: string,
        @Arg('password') password: string
    ) {
        //check if a user exists
        const user = await User.findOne({ where: { email } });
        if (user) {
            throw new Error('An account with that email address already exists.');
        }

        //add a new user
        const hashedPassword = await hash(password, 12);

        try {
            await User.insert({
                email,
                password: hashedPassword
            });
            return true;
        } catch (err) {
            console.log(err);
            return false;
        }
    }

    @Mutation(() => LoginResponse)
    async login(
        @Arg('email') email: string,
        @Arg('password') password: string,
        @Ctx() { res }: MyContext
    ): Promise<LoginResponse> {
        const user = await User.findOne({ where: { email } });

        if (!user) {
            throw new Error('Could not find user');
        }

        const valid = await compare(password, user.password);

        if(!valid) {
            throw new Error('Bad password');
        }

        //login successful

        sendRefreshToken(res, createRefreshToken(user));

        return {
            accessToken: createAccessToken(user),
            user
        }
    }

    @Mutation(() => Boolean)
    async revokeRefreshTokensForUser(
        @Arg('userId', () => Int) userId: number
    ) {
        await getConnection()
            .getRepository(User)
            .increment({ id: userId }, 'tokenVersion', 1);

        return true;
    }

    @Mutation(() => Boolean)
    async logout(
        @Ctx() { res }: MyContext
    ) {
        sendRefreshToken(res, '');
        return true;
    }
}