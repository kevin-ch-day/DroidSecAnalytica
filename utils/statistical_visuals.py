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
    sql = f"SELECT {category_column}, COUNT(*) FROM android_malware_hashes GROUP BY {category_column}"
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
        # Additional advanced analysis here
        file.write("\n")