from rasa.nlu.components import Component
from rasa.nlu import utils
from rasa.nlu.model import Metadata
import logging
from typing import Any, List, Type, Text, Dict, Union, Tuple, Optional
import pathlib
current_dir = pathlib.Path().resolve()
import nltk
nltk.download('vader_lexicon', download_dir=current_dir)
from nltk.sentiment import SentimentIntensityAnalyzer
import os
from rasa.shared.nlu.training_data.message import Message
from rasa.shared.nlu.constants import (
    INTENT,
    INTENT_NAME_KEY,
    INTENT_RANKING_KEY,
    PREDICTED_CONFIDENCE_KEY,
)
from rasa.core.constants import (
    DEFAULT_NLU_POSITIVE_THRESHOLD,
    DEFAULT_NLU_NEGATIVE_THRESHOLD,
    DEFAULT_ENABLE_INTENT_THRESHOLD,
)

positive_threshold = "positive_threshold"
negative_threshold = "negative_threshold"
enable_intent = "enable_intent"

class SentimentAnalyzer(Component):
    """A pre-trained sentiment component"""

    # please make sure to update the docs when changing a default parameter
    

    name = "sentiment"
    provides = ["entities"]
    requires = []
    defaults = {
        # If all intent confidence scores are beyond this threshold, set the current
        # intent to `FALLBACK_INTENT_NAME`
        positive_threshold: DEFAULT_NLU_POSITIVE_THRESHOLD,
        # If the confidence scores for the top two intent predictions are closer than
        # `AMBIGUITY_THRESHOLD_KEY`, then `FALLBACK_INTENT_NAME ` is predicted.
        negative_threshold: DEFAULT_NLU_NEGATIVE_THRESHOLD,

        enable_intent: DEFAULT_ENABLE_INTENT_THRESHOLD,
    }
    language_list = ["en"]

    def __init__(self, component_config):
        super(SentimentAnalyzer, self).__init__(component_config)

    def train(self, training_data, cfg, **kwargs):
        """Not needed, because the the model is pretrained"""
        pass
    
    # convert to rasa required format
    def convert_to_rasa(self, value, confidence):
        """Convert model output into the Rasa NLU compatible output format."""
        
        entity = {"value": value,
                  "confidence": confidence,
                  }

        return entity
    
    def check_sentimentParameters(self, threshold):
        
        if threshold in self.component_config:
            return True
        else:
            return False

    def process(self, message, **kwargs):
        """Retrieve the text message, pass it to the classifier
            and append the prediction results to the message class."""

        sid = SentimentIntensityAnalyzer()
        if 'text' in message.data:
            res = sid.polarity_scores(message.data['text'])
            key, value = max(res.items(), key=lambda x: x[1])

            entity = self.convert_to_rasa(key, value)
            actual_int = message.get("intent")
            actual_int['sentiment'] = key
            message.set("intent", actual_int, add_to_output=True)
            
            if self.check_sentimentParameters('positive_threshold'):
                positive_threshold = self.component_config['positive_threshold']
            else:
                positive_threshold = DEFAULT_NLU_POSITIVE_THRESHOLD
            
            if self.check_sentimentParameters('negative_threshold'):
                negative_threshold = self.component_config['negative_threshold']
            else:
                negative_threshold = DEFAULT_NLU_NEGATIVE_THRESHOLD

            if 'enable_intent' in self.component_config and self.component_config['enable_intent'] == True:
                if key == 'pos' and value >= positive_threshold:
                    message.data['intent']['name'] = 'nlu_positive'
                    message.data['intent']['confidence'] = 1.0
                    message.data['intent_ranking'].insert(0, {INTENT_NAME_KEY:'nlu_positive', PREDICTED_CONFIDENCE_KEY: 1.0})
                elif key == 'neg' and value >= negative_threshold:
                    message.data['intent']['name'] = 'nlu_negative'
                    message.data['intent']['confidence'] = 1.0
                    message.data['intent_ranking'].insert(0, {INTENT_NAME_KEY:'nlu_negative', PREDICTED_CONFIDENCE_KEY: 1.0})
            else:
                pass

    def persist(self, file_name, model_dir):
        """Pass because a pre-trained model is already persisted"""

        pass