const crypto = require("crypto");
const { user } = require("../../models");

// 비밀번호 암호화
module.exports = encryptPassword = async (unhashedPassword) => {
  let encrypted = await createHashedPassword(unhashedPassword);
  return encrypted;
};

// 비밀번호 해싱하기
const createHashedPassword = (unhashedPassword) => {
  return new Promise(async (res, rej) => {
    // salt
    const salt = await createSalt();
    // 암호화 되지 않은 비밀번호와 salt값을 이용해 sha512로 hashing
    crypto.pbkdf2(unhashedPassword, salt, 17598, 64, "sha512", (err, key) => {
      // 비밀번호, salt, 반복횟수, 비밀번호 길이, 해시 알고리즘, 콜백
      if (err) rej(err);
      res({ password: key.toString("base64"), salt }); // base64 문자열 salt로 변경
    });
  });
};

// crypto 모듈의 randomBytes 메서드 통해 64비트 길이의 랜덤 salt 만들기
const createSalt = () => {
  return new Promise((res, rej) => {
    crypto.randomBytes(64, (err, buf) => {
      if (err) rej(err);
      res(buf.toString("base64")); // base64 문자열 salt로 변경
    });
  });
};
