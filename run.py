import numpy as np
from preprocessing import DataPreprocessor
from model import NetworkArchitecture

def main():
    try:
        # Load and preprocess data using your existing code
        df_train, df_test = load_data('KDDTrain+.txt', 'KDDTest+.txt')
        
        # Initialize data preprocessor
        preprocessor = DataPreprocessor(df_train, df_test)
        
        # Get processed data - this includes your validation set
        X_train, X_val, y_train, y_val, X_test, y_test = preprocessor.process()
        
        # Build model with same architecture
        input_shape = (X_train.shape[1],)
        num_classes = len(np.unique(y_train))
        model = NetworkArchitecture.build_cnn_model(input_shape, num_classes)
        
        # Load the weights
        print("Loading weights...")
        model.load_weights('best_model.h5')
        
        # Predict on validation set
        print("Making predictions on validation set...")
        predictions = model.predict(X_val)
        predicted_classes = np.argmax(predictions, axis=1)
        true_classes = np.argmax(y_val, axis=1)
        
        # Calculate and print accuracy
        accuracy = np.mean(predicted_classes == true_classes)
        print(f"\nValidation Accuracy: {accuracy:.4f}")
        
        # Print some sample predictions
        print("\nSample predictions (first 5):")
        for i in range(5):
            print(f"Sample {i+1}: Predicted: {predicted_classes[i]}, Actual: {true_classes[i]}")
        
        return model, predictions, predicted_classes, true_classes
        
    except Exception as e:
        print(f"Error occurred: {str(e)}")
        raise

if __name__ == "__main__":
    model, predictions, pred_classes, true_classes = main()