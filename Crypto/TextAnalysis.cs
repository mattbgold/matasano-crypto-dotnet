using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Crypto
{
    public static class TextAnalysis
    {
        private static readonly Dictionary<string, int> bigramScores = new Dictionary<string, int>()
	    {
		    {"th", 152}, {"he", 128}, {"in", 94}, {"er", 94}, {"an", 82}, {"re", 68}, {"nd", 63},
		    {"at", 59 }, {"on", 57},  {"nt", 56}, {"ha", 56}, {"es", 56}, {"st", 55}, {"en", 55},
		    {"ed", 53},  {"to", 52},  {"it", 50}, {"ou", 50}, {"ea", 47}, {"hi", 46}, {"is", 46},
		    {"or", 43},  {"ti", 34},  {"as", 33}, {"te", 27}, {"et", 19}, {"ng", 18}, {"of", 16},
		    {"al", 9},   {"de", 9},   {"se", 8},  {"le", 8},  {"sa", 6},  {"si" ,5},  {"ar", 4}, 
		    {"ve", 4},   {"ra", 4},   {"ld", 2},  {"ur", 2}
	    };

        public static string GetHighestScore(IEnumerable<string> candidates)
        {
            return candidates.OrderByDescending(c => GetScore(c)).First();
        }

        public static int GetScore(string str)
        {
            var spaceCount = str.Count(x => x == ' ');
            str = str.Replace(" ", "").ToLower();

            int score = 0;

            for (int i = 0; i < str.Length - 1; i++)
            {
                var bigram = str[i].ToString() + str[i + 1].ToString();
                if (bigramScores.ContainsKey(bigram))
                {
                    score += bigramScores[bigram];
                }
                else
                {
                    if (str[i] < 32)
                    {
                        if (str[i] != 10)
                        {
                            score -= 50;
                        }
                    }
                    else if (Char.IsLetterOrDigit(str[i]))
                    {
                        if (Char.IsLower(str[i]))
                        {
                            score += 10;
                        }
                        else
                        {
                            score += 5;
                        }
                    }
                    else if(Char.IsPunctuation(str[i]))
                    {
                        score += 3;
                    }
                    else if (str[i] == 32)
                    {
                        score += 20;
                    }
                    else
                    {
                        score -= 5;
                    }
                }
            }
            return score;
        }
    }
}
