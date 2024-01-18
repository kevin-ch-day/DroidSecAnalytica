from scipy.stats import binomtest
import pycountry

def interpret_detection_ratio(detection_ratio):
    if detection_ratio < 1:
        return "Extremely low detection ratio suggests minimal maliciousness."
    elif detection_ratio < 5:
        return "Very low detection ratio indicates a very low-level threat."
    elif detection_ratio < 15:
        return "Low detection ratio indicates a potential low-level threat."
    elif detection_ratio < 50:
        return "Moderate detection ratio suggests a significant threat."
    else:
        return "High detection ratio indicates a high likelihood of maliciousness."

def analyze_positive_scanners(positives):
    if positives > 20:
        return "A significant number of scanners detected the file as malicious."
    elif positives > 5:
        return "Several scanners detected the file as malicious, indicating a potential threat."
    else:
        return "A few scanners detected the file as malicious, consider further investigation."

def recommend_based_on_detection(detection_ratio):
    if detection_ratio > 75:
        return "Recommendation: Highly likely to be malicious, immediate action needed."
    elif detection_ratio > 50:
        return "Recommendation: High likelihood of maliciousness, investigate and take precautions."
    else:
        return "Recommendation: Monitor for any changes."

def statistical_analysis(positives, total, significance_level=0.05):
    if total < 10:
        return "Insufficient data for statistical analysis."
    
    p_value = binomtest(positives, total, p=significance_level).pvalue
    
    analysis = "Data Science Analysis:"
    recommendation = "Recommendation:"
    
    # Detection Analysis
    if positives == 0:
        analysis += "\n- No scanners detected this file as malicious."
        recommendation += "\n- No immediate action required, but monitor for changes."
    else:
        analysis += f"\n- {positives} out of {total} scanners detected this file as malicious."
        detection_ratio = (positives / total) * 100
        
        if detection_ratio < 5:
            analysis += "\n- Very low detection ratio suggests minimal maliciousness."
        elif detection_ratio < 15:
            analysis += "\n- Low detection ratio indicates potential low-level threat."
        elif detection_ratio < 50:
            analysis += "\n- Moderate detection ratio suggests a significant threat."
        else:
            analysis += "\n- High detection ratio indicates a high likelihood of maliciousness."
        
        # Statistical Analysis
        if p_value < significance_level:
            analysis += "\nStatistical Analysis:"
            analysis += "\n- Significant deviation from the expected detection rate."
            if positives > 10:
                recommendation += "\n- Highly confident that the detection is accurate. Immediate action needed."
            elif positives > 0:
                recommendation += "\n- Highly confident that the detection is accurate. Investigate immediately."
            else:
                recommendation += "\n- Highly confident that the detection is accurate. Monitor for changes."
        else:
            analysis += "\nStatistical Analysis:"
            analysis += "\n- No significant deviation from the expected detection rate."
            recommendation += "\n- Further investigation recommended to confirm accuracy."
    
    return f"{analysis}\n\n{recommendation}"

def get_country_info(country_code):
    try:
        country = pycountry.countries.get(alpha_2=country_code)
        if country:
            continent = pycountry.subdivisions.get(code=f"{country.alpha_2}01")
            if continent:
                continent_name = continent.name
            else:
                continent_name = "Unknown"
            return f"Continent: {continent_name}, Name: {country.name}, Alpha-2 Code: {country.alpha_2}, Alpha-3 Code: {country.alpha_3}"
        else:
            return "Country not found in the pycountry database."
    except Exception as e:
        return f"Error fetching country information: {str(e)}"

def geographic_analysis(results):
    if 'country' in results:
        detected_countries = results['country']
        country_count = len(detected_countries)
        
        if country_count == 0:
            return "\nNo geographic information available."
        
        elif country_count == 1:
            country = detected_countries[0]
            country_info = get_country_info(country)
            return f"Detected Country: {country} ({country_info})"
        
        else:
            country_frequency = {}
            for country in detected_countries:
                if country in country_frequency:
                    country_frequency[country] += 1
                else:
                    country_frequency[country] = 1
            
            sorted_countries = sorted(country_frequency.items(), key=lambda x: x[1], reverse=True)
            summary = "Detected Countries and Frequencies:\n"
            for country, frequency in sorted_countries:
                country_info = get_country_info(country)
                summary += f"{country} ({country_info}): {frequency} times\n"
            
            return summary
    
    return "\nNo geographic information available."

def print_data_science_analysis(results):
    if 'error' in results:
        print(f'Error: {results["error"]}')
        return
    
    positives = results['positives']
    total = results['total']
    print(f"Analysis: {positives} out of {total} scanners detected this file as malicious.")
    
    detection_ratio = analyze_detection_ratio(positives, total)
    print(f"Detection Ratio: {detection_ratio:.2f}%")
    
    print(interpret_detection_ratio(detection_ratio))
    print(analyze_positive_scanners(positives))
    print(recommend_based_on_detection(detection_ratio))
    print(statistical_analysis(positives, total))
    print(geographic_analysis(results))
    print(behavioral_analysis(results))