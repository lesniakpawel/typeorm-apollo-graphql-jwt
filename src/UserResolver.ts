import {Resolver, Query, Mutation, Arg} from "type-graphql";
import {User} from "./entity/User";
import {hash} from 'bcryptjs';

@Resolver()
export class UserResolver {
    @Query(() => String)
    hello() {
        return 'hi!';
    }

    @Query(() => [User])
    users() {
        return User.find();
    }

    @Mutation(() => Boolean)
    async register(
        @Arg('email') email: string,
        @Arg('password') password: string
    ) {
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
}