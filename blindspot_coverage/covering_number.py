# coding=utf-8
"""
Python module for computing coverage number
"""
import pybloomfilter


class CoveringNumber(object):
    """
    Class to implement Eq.(4) of the paper
    """

    def __init__(self, num_samples, expected_num_points, batch_size, error_rate=0.000001):
        self._num_samples = num_samples
        self._batch_size = batch_size
        self._expected_num_points = expected_num_points
        self._denominator = [0.] * num_samples
        self._numerator = [0.] * num_samples

        self._bf = pybloomfilter.BloomFilter(expected_num_points, error_rate)
        self._actual_num_points = 0.

    def update_denominator(self, sample_idx, sample):
        """
        Computes the denominator of the sample_idxth sample of the training data.
        This method needs to be called once as the denominator is constant regardless of the adversarial learning
        process
        :param sample_idx: index of the training sample
        :param sample: the original form of the training sample
        :return:
        """
        self._denominator[sample_idx] = len(sample) - torch.dot(sample, torch.ones(sample.size()))

    def update_numerator(self, sample_idx, point):
        """
        update the numerator counter for the sample_idxth point by testing if point has already been visited
        :param sample_idx: index of the training sample
        :param point: current version of the training sample
        :return:
        """
        pt_np = point.numpy()
        is_not_in = not self._bf.add(hash(str(pt_np)))
        self._numerator[sample_idx] += int(is_not_in)
        self._actual_num_points += int(is_not_in)

    def update_numerator_batch(self, batch_idx, batch):
        """
        update the covering number measure with the new batch
        :param batch_idx: current batch index
        :param batch: batch features in tensor float (these will be hashed in against bloom filter
        :return:
        """
        for point_idx, point in enumerate(batch):
            sample_idx = point_idx + self._batch_size * batch_idx
            self.update_numerator(sample_idx, point)

    def ratio(self):
        """
        :return: the ratio of the visited samples to the maximum expected ones
        """
        return self._actual_num_points * 1. / self._expected_num_points

    def num_pts(self): return self._actual_num_points

    def exp_num_pts(self): return self._expected_num_points


if __name__ == "__main__":
    print("I am just a module to be called by others, testing here")
    import torch
    _num_samples = 10
    epochs = 100
    _expected_num_points = _num_samples * epochs
    _batch_size = 2

    bscn = CoveringNumber(_num_samples, _expected_num_points, _batch_size)

    _batch = torch.rand(_batch_size, 1)

    print(_batch)
    bscn.update_numerator_batch(2, _batch)
    print("done")
    print(bscn.ratio())
    print(_batch)
    bscn.update_numerator_batch(2, _batch)

    print(bscn.ratio())
