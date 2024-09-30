# statistical_visuals.py

import matplotlib.pyplot as plt
import seaborn as sns
import plotly.express as px
from sklearn.cluster import KMeans
import pandas as pd

OUTPUT_DIR = "output\\"

def generate_bar_chart(data, title, xlabel, ylabel, filename, color_palette=None, rotate_labels=False):
    print("\nGenerating bar chart...")
    
    if not isinstance(data, dict):
        print("Error: Data is not of a dictionary type.")
        return
    
    data_df = pd.DataFrame(list(data.items()), columns=['Index', 'Value'])
    plt.figure(figsize=(10, 6))
    sns.barplot(x='Index', y='Value', data=data_df, palette=color_palette)
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    if rotate_labels:
        plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    plt.savefig(OUTPUT_DIR + filename)
    plt.close()

def generate_pie_chart(data, title, filename, colors=None, verbose=True):
    print("\nGenerating pie chart...")
    try:
        # Check if data is a pandas Series and extract it if so
        if isinstance(data, dict):
            data_key = 'risk_category_percentages'
            if data_key in data and isinstance(data[data_key], pd.Series):
                data_series = data[data_key]
            else:
                raise ValueError(f"Key '{data_key}' is not present or not a pandas Series.")
        elif isinstance(data, pd.Series):
            data_series = data
        else:
            raise ValueError("Data must be a pandas Series or a dict with pandas Series.")
        
        # Ensure all values are numeric
        if not all(isinstance(x, (int, float)) for x in data_series):
            raise ValueError("All data values must be numeric.")
        
        # Generate pie chart
        plt.figure(figsize=(8, 8))
        plt.pie(data_series.values, labels=data_series.index, autopct='%1.1f%%', startangle=140, colors=colors)
        plt.title(title)
        plt.axis('equal')  # Ensure pie chart is a circle
        plt.tight_layout()
        plt.savefig(OUTPUT_DIR + filename)
        plt.close()

        if verbose:
            print("Pie chart generated successfully.")
    
    except Exception as e:
        print(f"An error occurred during visualization generation: {e}")

def generate_histogram(data, title, xlabel, ylabel, filename, color=None):
    print("\nGenerating histogram...")
    plt.figure(figsize=(10, 6))
    sns.histplot(data, kde=True, color=color)
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.tight_layout()
    plt.savefig(OUTPUT_DIR + filename)
    plt.close()

def generate_scatter_plot(x, y, title, xlabel, ylabel, filename, color=None, marker='o'):
    print("\nGenerating scatter plot...")
    plt.figure(figsize=(10, 6))
    plt.scatter(x, y, color=color, marker=marker)
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.tight_layout()
    plt.savefig(OUTPUT_DIR + filename)
    plt.close()

def generate_line_plot(x, y, title, xlabel, ylabel, filename, color=None, line_style='-'):
    print("\nGenerating line plot...")
    plt.figure(figsize=(10, 6))
    plt.plot(x, y, color=color, linestyle=line_style)
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.tight_layout()
    plt.savefig(OUTPUT_DIR + filename)
    plt.close()

def generate_box_plot(data, title, xlabel, ylabel, filename, color_palette=None):
    print("\nGenerating box plot...")
    plt.figure(figsize=(10, 6))
    sns.boxplot(data=data, palette=color_palette)
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.tight_layout()
    plt.savefig(OUTPUT_DIR + filename)
    plt.close()

def visualize_category_distribution_interactive(df, category_column):
    fig = px.bar(
        df.sort_values('Count', ascending=False), 
        x=category_column, 
        y='Count',
        title=f'Distribution of {category_column} - Total Counts',
        labels={'Count': 'Total Count', category_column: 'Category'},
        template='plotly_white'
    )
    fig.update_layout(
        xaxis_title="Category",
        yaxis_title="Total Count",
        xaxis_tickangle=-45
    )
    fig.write_image(f'output/{category_column}_distribution.png')
    fig.show()

def visualize_clusters_interactive(df):
    fig = px.scatter(
        df, 
        x='Name1', 
        y='Count', 
        color='Cluster', 
        title='Cluster Distribution in Combined Category Data',
        labels={'Count': 'Count', 'Name1': 'Primary Category'},
        template='plotly_white',
        hover_data=['Name1', 'Name2']  # Show additional data on hover
    )
    fig.update_traces(marker=dict(size=12, opacity=0.8, line=dict(width=2, color='DarkSlateGrey')))
    fig.update_layout(
        xaxis_title="Primary Category",
        yaxis_title="Count",
        legend_title="Cluster"
    )
    fig.write_image('output/combined_category_clusters.png')
    fig.show()

def visualize_clusters(df):
    plt.figure(figsize=(12, 8))
    
    # Adjust the transparency (alpha) if points are dense
    sns.scatterplot(data=df, x='Name1', y='Count', hue='Cluster', palette='viridis', alpha=0.7)
    
    plt.title('Cluster Distribution in Combined Category Data')
    plt.xlabel('Primary Category')
    plt.ylabel('Count')
    
    # Ensure the legend does not obscure the data
    plt.legend(title='Cluster', loc='upper right')
    
    # Rotate x-axis labels if they are dense
    plt.xticks(rotation=45, ha='right')
    
    # Annotations for key findings or unusual data points
    # Example: annotating the highest count in each cluster
    for cluster in df['Cluster'].unique():
        cluster_data = df[df['Cluster'] == cluster]
        highest_point = cluster_data.loc[cluster_data['Count'].idxmax()]
        plt.text(x=highest_point['Name1'], y=highest_point['Count'], s='Highest', color='red')
    
    plt.tight_layout()  # Adjust the plot to ensure everything fits without overlapping
    plt.savefig('output/combined_category_clusters.png')
    plt.close()

def cluster_insights(df):
    # Preparing the data for clustering
    # For demonstration, let's assume we're using 'Count' as the feature for clustering
    X = df[['Count']].values
    
    # Determine the optimal number of clusters, for this example we choose 3
    kmeans = KMeans(n_clusters=3, random_state=0).fit(X)
    df['Cluster'] = kmeans.labels_

    # Visualization of Clusters
    visualize_clusters(df)

def visualize_category_distribution(df, category_column):
    plt.figure(figsize=(12, 8))
    sns.barplot(x=category_column, y='Count', data=df.sort_values('Count', ascending=False))
    plt.title(f'Distribution of {category_column} - Total Counts')
    plt.xlabel('Category')
    plt.ylabel('Total Count')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()  # Adjust the plot to ensure everything fits without overlapping
    plt.savefig(f'output/{category_column}_distribution.png')
    plt.close()

def advanced_category_analysis(cursor, file, category_column):
    """ Advanced helper function to write category data with predictive analytics and visualization. """
    sql = f"SELECT {category_column}, COUNT(*) FROM android_malware_threat_metadata GROUP BY {category_column}"
    cursor.execute(sql)
    category_data = cursor.fetchall()

    if not category_data:
        file.write(f"No data available for {category_column}.\n\n")
        return

    # Convert data to DataFrame for advanced analysis
    df = pd.DataFrame(category_data, columns=[category_column, 'Count'])
    
    # Predictive Analytics: Example - Forecasting future trends
    # Visualization: Category distribution
    visualize_category_distribution(df, category_column)

    # Writing analysis results to file
    for category, count in category_data:
        category_str = category if category else "Unknown"
        file.write(f"**{category_str}**\n")
        file.write(f"Category Count: {count} entries\n")
        file.write("\n")