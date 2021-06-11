const { user } = require("../../models");

module.exports = {
	get: async (req, res) => {

		console.log('get userinfo request')

		let userId = req.session.userId;

		console.log(userId)

		if (!userId) {
      res.status(404).send({ data: null, message: 'not found' });
    } else {
      const data = await user.findOne({
        where: { id: userId },
			}).catch((err) => res.json(err));

			delete data.dataValues.password;

			res.status(200).json({
				data: data.dataValues,
				message: 'ok'
			});
		}
	}
}