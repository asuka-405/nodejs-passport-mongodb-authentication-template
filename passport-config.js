const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
function initPassport(passport, userDB) {
    let user
    const authUser = async (username, password, done) => {
        user  = await userDB.findOne({username: username});
        if (user == null) {
            return done(null, false, {message: "no user found"});
        }
        try {
            if(await bcrypt.compare(password, user.password)){
                return done(null, user);
            }else{
                return done(null, false, {message: "incorrect password"});
            }
        }catch(err){
            return done(err);
        }
    }
    // new LocalStrategy({usernameField: 'username', passwordField: 'password'}, authUser)
    passport.use(new LocalStrategy(authUser))
    passport.serializeUser((user, done)=>{
        done(null, user.id)
    });
    passport.deserializeUser(async(id, done)=>{
        if (user) {
               return done(null, user);
        }
        return done(null, false)
    });
}
module.exports = initPassport;