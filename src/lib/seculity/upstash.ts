import { headers } from "next/headers";
import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";

//////////
//■[ UpstashでrateLimitを実装 ]
//＊https://claude.ai/chat/8504a412-36aa-4e6a-b204-908030a3361f
//・Redisクライアントの作成
const redis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL || '',
  token: process.env.UPSTASH_REDIS_REST_TOKEN || '',
});
//・レートリミットの設定（5リクエスト/10分）
const ratelimitConfig = new Ratelimit({
  redis,
  limiter: Ratelimit.slidingWindow(
    5, 
    '10m'//`${number} ms` | `${number} s` | `${number} m` | `${number} h` | `${number} d` | `${number}ms` | `${number}s` | `${number}m` | `${number}h` | `${number}d`
  ),
  analytics: true,
});
//・rateLimit
export const rateLimit = async():Promise<{
  success:boolean
  message:string
}> => {
  console.log('--rateLimit()--')
  //////////
  // ■[ ユーザー識別子を定義。今回は「IPアドレス_user-agent」とする ]
  const headersList = await headers();
  const ip = headersList.get('x-forwarded-for') || 'unknown-ip';
  console.log(`ip:${ip}`)//開発環境では、おそらく「::1_」と出力される
    //## ループバックアドレス:
    //  - コンピューターが自分自身と通信するために使用する特別なIPアドレス
    //  - 通常「localhost」としても知られる
    //  - IPv4では「127.0.0.1」、IPv6では「::1」
  const userAgent = headersList.get('user-agent') || 'unknown-agent';
  const identifier = `${ip}_${userAgent}`;// IPとUser-Agentを組み合わせた識別子を作成
    //## IPだけでなくUser-Agentも組み合わせる理由
    //  - 企業や学校などでは、複数ユーザーが同じIPを共有している場合が
    //  - 公共Wi-Fiでは、多くのユーザーが同じIPを使用する

  //////////
  //■[ レートリミットを実行 ]
  const { success, limit, reset, remaining } = await ratelimitConfig.limit(
    `smsAuth_${identifier}`
  );
  console.log(`success:${success}`)
  console.log(`limit:${limit}`)
  console.log(`reset:${reset}`)
  console.log(`remaining:${remaining}`)
  if (!success) {
    // レート制限に達した場合
    return {
      success:false, 
      message:`Too many requests. Please try again after ${Math.ceil((reset - Date.now()) / 1000)} seconds.`
    };
  }
  // 処理結果を返す
  return { success: true, message: 'Form submitted successfully' };
}