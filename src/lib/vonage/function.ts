import axios from "axios";
const api_key = process.env.VonageApiKey;
const api_secret = process.env.VonageApiSecret;

export const sendSmsAuth = async ({
  phoneNumber,
  text,
  from = 'fromNext',
}: {
  phoneNumber: string,
  text: string,
  from?: string
}): Promise<{ result: boolean, message: string }> => {
  try {
    const modifiedNumber = phoneNumber.replace(/^0/, '81'); // 冒頭の「0」を日本の国番号「81」に変換
    const to = modifiedNumber;

    console.log(
      api_key,
      api_secret,
      to,
      from,
      text)

    const {data} = await axios.post('https://rest.nexmo.com/sms/json', {
      api_key,
      api_secret,
      to,
      from,
      text
    });

    if (data.messages[0].status !== '0')throw new Error(data.messages[0]['error-text'])
    console.log(`cost:${data.messages[0]['message-price']}`)

    return {
      result: true,
      message: 'success'
    };

  } catch (err) {
    const errMessage = err instanceof Error ?  ` ${err.message}` : ``;
    return {
      result: false,
      message: `Failed to send verification sms. Please check your telephone number and try again. ${errMessage}`
    };
  }
};
