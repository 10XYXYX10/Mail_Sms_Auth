import Image from 'next/image';

const articles = [
  {
    title: 'Next.js V15：フルスタック開発！AWS S3×CloudFront×WAFで画像ファイルを安全＆高速配信！',
    imgPath: '/img/articlePostApp.jpg',
    imgWidth: 750,
    imgHeight: 422,
    url: 'https://www.udemy.com/course/nextjs-v15aws-s3cloudfront/?referralCode=CB50C65B7C8C4EA37993'
  },
  {
    title: '喋るAIのディベート対決！OpenAI-Assistants API×VOICEVOX×Next.jsでフルスタック開発',
    imgPath: '/img/debatingAi.jpg',
    imgWidth: 750,
    imgHeight: 422,
    url: 'https://www.udemy.com/course/aiopenai-assistants-apivoicevoxnextjs/?referralCode=EB51E25A14B11F0B9D54'
  }
];

const MainPage = () => {
  return (
    <div className="max-w-6xl mx-auto py-12 px-4 sm:px-6 lg:px-8 mb-10">
      <h2 className="text-3xl font-bold text-center mb-12 text-gray-800">おすすめの講座</h2>
      
      <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
        {articles.map((article, index) => (
          <a 
            key={index} 
            href={article.url} 
            target="_blank" 
            className="group"
          >
            <div className="bg-white rounded-lg overflow-hidden shadow-lg transition-all duration-300 transform hover:-translate-y-2 hover:shadow-xl h-full flex flex-col">
              <div className="p-4 border-b">
                <h3 className="text-xl font-semibold text-gray-800 group-hover:text-blue-600 transition-colors duration-200">
                  {article.title}
                </h3>
              </div>
              
              <div className="w-full px-2 py-5">
                <Image 
                  src={article.imgPath} 
                  alt={article.title}
                  width={article.imgWidth}
                  height={article.imgHeight}
                  className="object-contain"
                />
              </div>
              
              <div className="p-4 flex-grow flex flex-col">
                <div className="flex justify-between items-center mt-auto">
                  <span className="inline-block bg-blue-100 text-blue-800 text-sm font-medium px-3 py-1 rounded-full">
                    Udemy講座
                  </span>
                  <span className="text-gray-500 text-sm flex items-center group-hover:text-blue-600">
                    詳細を見る
                    <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 ml-1 transition-transform duration-200 group-hover:translate-x-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                    </svg>
                  </span>
                </div>
              </div>
            </div>
          </a>
        ))}
      </div>
    </div>
  );
};
export default MainPage;