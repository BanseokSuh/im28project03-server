const { user } = require("../../models");
const getHashedPassword = require("./getHashedPassword");

module.exports = {
  post: async (req, res) => {
    const { email, password } = req.body;

    // 사용자의 salt값과 암호화 되지 않은 비밀번호를 조합하여 사용자의 비밀번호를 조회한다.
    let hashedPassword = await getHashedPassword(email, password);

    req.session.regenerate(async () => {
      try {
        const foundUser = await user.findOne({
          where: {
            email: email,
            password: hashedPassword,
          },
        });

        if (!foundUser)
          return res.status(404).send("조회된 사용자 정보가 없습니다.");

        // 세션 스토어에 저장!
        req.session.save(function () {
          req.session.userId = foundUser.id;
          res.status(200).send({
            id: foundUser.id,
          });
        });
      } catch (e) {
        res.status(404).send(e);
      }
    });
  },
};
