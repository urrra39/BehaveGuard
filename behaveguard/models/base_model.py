"""Abstract base contract for every BehaveGuard anomaly detector.

This module is deliberately **torch-free at import time**. It defines a pure
:class:`abc.ABC` describing the shape every detector must satisfy. The two
concrete helpers that *do* need torch — :meth:`BaseDetector.save` and
:meth:`BaseDetector.load` — import it lazily inside the method body, so simply
``import behaveguard.models.base_model`` never pulls in torch or numpy. This is
what lets the torch-free packages of BehaveGuard (and the test suite) reason
about the detector contract without a deep-learning stack installed.

Concrete detectors are expected to be *mixed* with :class:`torch.nn.Module`::

    class LSTMDetector(torch.nn.Module, BaseDetector):
        ...

Because :class:`torch.nn.Module` does not declare a custom metaclass and
:class:`BaseDetector` carries :class:`abc.ABCMeta`, the resulting class's
metaclass resolves cleanly to :class:`abc.ABCMeta` (the most-derived metaclass),
so the multiple-inheritance combination is well defined. The mixin provides
``state_dict()`` / ``load_state_dict()`` / ``eval()`` which :meth:`save` and
:meth:`load` rely on.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict

if TYPE_CHECKING:  # pragma: no cover - typing only
    import torch


class BaseDetector(ABC):
    """Common interface shared by all anomaly-detection models.

    Subclasses must also inherit from :class:`torch.nn.Module` so that the
    persistence helpers (:meth:`save` / :meth:`load`) can use the standard
    ``state_dict`` machinery. The abstract surface below is what every consumer
    in the BehaveGuard pipeline relies on, regardless of the concrete
    architecture behind it.
    """

    #: Short discriminator written into every checkpoint and used by
    #: :class:`behaveguard.models.model_store.ModelStore` to pick the right class
    #: when reconstructing a saved model. Overridden by each subclass.
    model_type: str = "base"

    # ------------------------------------------------------------------ #
    # Abstract surface every detector must implement.
    # ------------------------------------------------------------------ #
    @abstractmethod
    def forward(self, x: "torch.Tensor") -> Any:
        """Run the forward pass.

        The concrete return type is architecture specific (e.g. a
        ``(reconstruction, hidden)`` tuple for the LSTM, or
        ``(reconstruction, mu, logvar)`` for the VAE). Defined as abstract here
        purely so that the mixed-in :class:`torch.nn.Module` always has a
        concrete ``forward`` provided by the subclass.

        Args:
            x: Input tensor whose shape depends on the concrete model.

        Returns:
            The model-specific forward output.
        """
        raise NotImplementedError

    @abstractmethod
    def anomaly_score(self, x: "torch.Tensor") -> float:
        """Return a calibrated anomaly score in the closed interval ``[0, 1]``.

        ``0.0`` means "looks exactly like the learned baseline" and ``1.0`` means
        "maximally anomalous". Implementations are expected to run in eval mode
        without gradient tracking and to squash a baseline-relative error through
        a sigmoid (or equivalent) so the output is always bounded.

        Args:
            x: Input sample (or batch) to score.

        Returns:
            A single python ``float`` in ``[0, 1]`` (mean over the batch).
        """
        raise NotImplementedError

    @abstractmethod
    def get_config(self) -> Dict[str, Any]:
        """Return the constructor keyword arguments needed to rebuild this model.

        The returned mapping is serialized verbatim into the checkpoint by
        :meth:`save` and splatted back into ``cls(**config)`` by :meth:`load`, so
        it must contain exactly the architecture-defining ``__init__`` arguments
        (and nothing that is not a constructor parameter).

        Returns:
            A JSON-serializable dict of constructor kwargs.
        """
        raise NotImplementedError

    # ------------------------------------------------------------------ #
    # Concrete persistence helpers (torch imported lazily).
    # ------------------------------------------------------------------ #
    def save(self, path: str) -> None:
        """Serialize weights, ``model_type``, and config to ``path``.

        Parent directories are created if missing. ``torch`` is imported lazily
        so that importing this module never requires a deep-learning stack.

        Args:
            path: Destination file path for the checkpoint.
        """
        import torch  # local import keeps the module torch-free at import time

        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        checkpoint: Dict[str, Any] = {
            "state_dict": self.state_dict(),  # type: ignore[attr-defined]
            "model_type": self.model_type,
            "config": self.get_config(),
        }
        torch.save(checkpoint, str(target))

    @classmethod
    def load(cls, path: str, map_location: str = "cpu") -> "BaseDetector":
        """Reconstruct a model previously written by :meth:`save`.

        The class is instantiated from the stored ``config``, the saved weights
        are loaded, and the model is switched to eval mode before being returned.

        Args:
            path: Path to a checkpoint produced by :meth:`save`.
            map_location: Device mapping passed straight through to
                :func:`torch.load` (defaults to ``"cpu"``).

        Returns:
            The reconstructed detector instance in eval mode.
        """
        import torch  # local import keeps the module torch-free at import time

        checkpoint: Dict[str, Any] = torch.load(str(path), map_location=map_location)
        model = cls(**checkpoint["config"])
        model.load_state_dict(checkpoint["state_dict"])  # type: ignore[attr-defined]
        model.eval()  # type: ignore[attr-defined]
        return model
